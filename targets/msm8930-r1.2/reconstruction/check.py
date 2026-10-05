#!/usr/bin/env python3
"""Offline byte-exactness gate for the bn_from_bytes reconstruction.

Compiles ARM code with arm-none-eabi-gas at the ROM address and compares every
byte against the pinned PBL artifact. Nothing is executed.

ROM: targets/msm8930-r1.2/pbl.bin
Range reconstructed: 0x00004554..0x000045FF (172 bytes, 43 ARM words).

Run from the repository root:

    python3 targets/msm8930-r1.2/reconstruction/check.py

The reconstruction covers the bignum loader at 0x4554. This is the
length-carrying primitive on the ROM's signature-verification path: callers
feed it a byte length parsed from the image, and nothing on that path
re-binds the length to the RSA modulus size (0xbdf8..0xbffc applies a fixed
2048..4096-bit window only). Byte-exact reproduction of the loader pins that
behaviour so later analysis can read assembly instead of raw listings.
"""

import hashlib
import shlex
import shutil
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TARGET = HERE.parent
ROM_PATH = TARGET / "pbl.bin"
ROM_SHA256 = "c1a7d8ffc9a3b9581953107861e61d9d7d9b9b2c5dafd929571446614884f92e"
ROM_SIZE = 131072
ROM_BASE = 0x00000000
RECON_ADDRESS = 0x00004554
RECON_SIZE = 172

TOOLS = ("as", "ld", "objcopy", "objdump")
TOOL_PREFIX = "arm-none-eabi-"


class GateError(Exception):
    pass


class IdentityError(GateError):
    pass


class ByteMismatch(GateError):
    pass


def identify_rom(data):
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != ROM_SIZE or digest != ROM_SHA256:
        raise IdentityError(f"ROM identity: {len(data)} bytes, sha256 {digest}")


def require_match(actual, expected, label):
    if actual != expected:
        first = next(
            (i for i, (a, b) in enumerate(zip(actual, expected)) if a != b),
            min(len(actual), len(expected)),
        )
        word = first // 4
        raise ByteMismatch(
            f"{label}: {len(actual)} bytes vs expected {len(expected)}; "
            f"first difference at literal +0x{first:x} (instruction #{word}, "
            f"ROM 0x{RECON_ADDRESS + 4 * word:08x})"
        )


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise GateError(f"mutation anchor must occur exactly once: {old!r}")
    return source.replace(old, new)


def check_elf(path, address, binary_size):
    elf = path.read_bytes()
    if elf[:7] != b"\x7fELF\x01\x01\x01":
        raise GateError(f"{path.name}: not ELF32 little-endian")
    header = struct.unpack_from("<16sHHIIIIIHHHHHH", elf)
    if header[1:4] != (2, 40, 1) or header[4] != address:
        raise GateError(f"{path.name}: wrong ELF type, machine, or entry")
    section_offset, section_stride, section_count = header[6], header[11], header[12]
    if section_stride != 40 or not section_count:
        raise GateError(f"{path.name}: unexpected ELF section table")
    allocated = []
    for index in range(section_count):
        section = struct.unpack_from("<10I", elf, section_offset + index * 40)
        if section[2] & 2 and section[5]:  # SHF_ALLOC, nonempty
            allocated.append(section)
    if (len(allocated) != 1 or allocated[0][1] != 1
            or allocated[0][3] != address or allocated[0][5] != binary_size):
        raise GateError(f"{path.name}: expected one measured PROGBITS section")


class Builder:
    def __init__(self, directory, log_path):
        self.tools = {name: TOOL_PREFIX + name for name in TOOLS}
        for tool in self.tools.values():
            if shutil.which(tool) is None:
                raise GateError(f"missing offline tool: {tool}")
        directory.mkdir(parents=True, exist_ok=True)
        self.directory = directory
        self.log_path = log_path
        self.log_path.write_text("", encoding="utf-8")

    def run(self, name, *args):
        command = [self.tools[name], *map(str, args)]
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, check=False)
        with self.log_path.open("a", encoding="utf-8") as log:
            log.write("$ " + shlex.join(command) + "\n" + result.stdout)
            log.write(f"[exit {result.returncode}]\n\n")
        if result.returncode:
            raise GateError(f"tool failed: {shlex.join(command)}\n{result.stdout}")
        return result.stdout

    def build(self, label, source_text):
        source_path = self.directory / f"{label}.s"
        source_path.write_text(source_text, encoding="utf-8")
        obj = self.directory / f"{label}.o"
        elf = self.directory / f"{label}.elf"
        binary = self.directory / f"{label}.bin"
        self.run("as", "-mcpu=arm7tdmi", "-EL", source_path, "-o", obj)
        self.run("ld", "-EL", "-Ttext", f"0x{RECON_ADDRESS:08x}",
                 "--entry=bn_from_bytes", "--build-id=none", obj, "-o", elf)
        self.run("objcopy", "-O", "binary", elf, binary)
        data = binary.read_bytes()
        check_elf(elf, RECON_ADDRESS, len(data))
        disassembly = self.run("objdump", "-h", "-t", "-r", "-d", elf)
        (self.directory / f"{label}.dis").write_text(disassembly, encoding="utf-8")
        return data


def main():
    rom = ROM_PATH.read_bytes()
    identify_rom(rom)  # Before any compiler invocation.
    print(f"PASS ROM identity: {len(rom)} bytes, sha256 {ROM_SHA256}")

    build_dir = HERE / "build"
    builder = Builder(build_dir, HERE / "commands.log")
    print(builder.run("as", "--version").splitlines()[0])

    source = (HERE / "bn_from_bytes.s").read_text(encoding="utf-8")
    offset = RECON_ADDRESS - ROM_BASE
    expected = rom[offset:offset + RECON_SIZE]

    actual = builder.build("bn_from_bytes", source)
    require_match(actual, expected, "bn_from_bytes")
    print(f"PASS asm: {RECON_SIZE} exact bytes at 0x{RECON_ADDRESS:08x}, "
          f"sha256 {hashlib.sha256(actual).hexdigest()}")

    mutants = [
        ("asm-wrong-alloc-return", "movle   r0, #1", "movle   r0, #0"),
        ("asm-inverted-overflow-branch", "bgt     return_zero",
         "blt     return_zero"),
        ("asm-swapped-acc-shift", "orr     r5, r0, r5, lsl #8",
         "orr     r5, r0, r5, ror #8"),
    ]
    for label, old, new in mutants:
        mutated = replace_once(source, old, new)
        try:
            require_match(builder.build(label, mutated), expected, label)
        except ByteMismatch as error:
            print(f"PASS rejected compiled mutation: {error}")
        else:
            raise GateError(f"negative control unexpectedly matched: {label}")

    for label, bad_rom in (
            ("changed ROM byte", bytes([rom[0] ^ 1]) + rom[1:]),
            ("truncated ROM", rom[:-1])):
        try:
            identify_rom(bad_rom)
        except IdentityError:
            print(f"PASS rejected {label}")
        else:
            raise GateError(f"ROM identity unexpectedly accepted {label}")

    print("ALL GATES PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
