#!/usr/bin/env python3
"""Offline inspection of Bootromancy ROM targets.

A target directory contains:

    manifest.json  artifact identity: target name, artifact path, size,
                   sha256, base address, byte order and mode
    symbols.json   analyst annotations, each with byte-level evidence
    <artifact>     the ROM image, addressed from manifest base_address

Every command re-verifies the target before producing output: manifest schema
and target identity, artifact size and SHA-256, and every symbol's evidence
anchors against the ROM bytes. A mismatch fails the command; output is never
silently produced from a different revision of the artifact.

Commands:

    rom.py verify TARGET_DIRECTORY
    rom.py disasm TARGET_DIRECTORY START LENGTH
    rom.py words  TARGET_DIRECTORY START COUNT
    rom.py strings TARGET_DIRECTORY [--min-length N]
    rom.py symbols TARGET_DIRECTORY

START, LENGTH and COUNT accept decimal or 0x-prefixed hexadecimal. Results go
to stdout; diagnostics go to stderr with a non-zero exit status.

Symbols follow the contract: kind is function, label or data; confidence is
observed, inferred or candidate; addresses and names are unique; and every
symbol carries at least one evidence anchor whose address lies inside the
artifact and whose bytes match the ROM. Functions and labels must be 4-byte
aligned, so unaligned data uses kind 'data'. Extra fields are ignored, so the
map can carry review metadata without breaking the tools.

`disasm` is a bounded linear ARM (little-endian, ARM state) inspection of the
requested range, not a function-boundary finder, CFG builder or code/data
classifier. It decodes every aligned word in the range, marks words that do
not decode as ARM, and annotates only what the bytes establish: PC-relative
literal loads (literal address and value) and direct branch targets that land
on a known symbol. Indirect targets are not guessed at. No Thumb decoding is
attempted, because ARM state is the only mode established for the current
targets. `words` reports little-endian u32 values and numeric matches to known
symbols, not inferred pointers. Zero matches are suppressed to avoid flooding
zero-filled data with a reset-vector label. `strings` reports printable ASCII
runs at their ROM addresses. Generated listings belong in out/, not in Git.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_GRP_CALL, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, Cs
from capstone.arm import (
    ARM_GRP_JUMP,
    ARM_INS_LDR,
    ARM_INS_LDRB,
    ARM_OP_IMM,
    ARM_OP_MEM,
    ARM_REG_PC,
)

SUPPORTED_SCHEMA_VERSION = 1
SUPPORTED_BYTE_ORDER = "little"
SUPPORTED_MODE = "arm"
SYMBOL_KINDS = ("function", "label", "data")
SYMBOL_CONFIDENCES = ("observed", "inferred", "candidate")
MANIFEST_NAME = "manifest.json"
SYMBOLS_NAME = "symbols.json"
ARM_INSN_SIZE = 4
ARM_PC_BIAS = 8  # ARM state reads PC as the instruction address + 8
# PC-relative literal load widths we are willing to annotate (insn.id key).
LITERAL_LOAD_WIDTHS = {ARM_INS_LDR: 4, ARM_INS_LDRB: 1}
DEFAULT_MIN_STRING_LENGTH = 4
NOTE_COLUMN = 58


class TargetError(Exception):
    """A target directory that cannot be trusted for the requested operation."""


@dataclass(frozen=True)
class Evidence:
    """One byte-level anchor quoted from the ROM."""

    address: int
    data: bytes
    note: str


@dataclass(frozen=True)
class Symbol:
    """An analyst annotation anchored to bytes in the ROM."""

    address: int
    name: str
    kind: str
    confidence: str
    summary: str
    evidence: tuple[Evidence, ...]


@dataclass(frozen=True)
class Target:
    """A verified target: manifest, ROM bytes and validated symbols."""

    directory: Path
    manifest_path: Path
    manifest: dict
    artifact_path: Path
    data: bytes
    base: int
    symbols: tuple[Symbol, ...]

    @property
    def name(self) -> str:
        return self.manifest["target"]

    @property
    def artifact_name(self) -> str:
        return self.manifest["artifact"]["path"]

    @property
    def symbols_path(self) -> Path:
        return self.directory / SYMBOLS_NAME

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def sha256(self) -> str:
        return self.manifest["artifact"]["sha256"]

    @property
    def end(self) -> int:
        """First address past the artifact."""
        return self.base + self.size

    def contains(self, address: int, size: int = 1) -> bool:
        return address >= self.base and address + size <= self.end

    def symbol_index(self) -> dict[int, Symbol]:
        return {symbol.address: symbol for symbol in self.symbols}


def parse_number(text: object, what: str) -> int:
    """Parse a decimal or 0x-prefixed hexadecimal integer."""
    text = str(text).strip()
    base = 16 if text.lower().startswith("0x") else 10
    try:
        value = int(text, base)
    except ValueError:
        raise TargetError(
            f"{what}: not a decimal or 0x-prefixed hexadecimal number: {text!r}"
        ) from None
    if value < 0:
        raise TargetError(f"{what}: must not be negative: {text!r}")
    return value


def require_aligned(address: int, what: str) -> None:
    if address % ARM_INSN_SIZE:
        raise TargetError(
            f"{what}: 0x{address:x} is not {ARM_INSN_SIZE}-byte aligned"
            " (ARM-state addresses must be)"
        )


def load_json(path: Path) -> object:
    try:
        text = path.read_text()
    except OSError as exc:
        raise TargetError(f"{path}: cannot read: {exc}") from None
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise TargetError(f"{path}: invalid JSON: {exc}") from None


def parse_hex_bytes(text: object, what: str) -> bytes:
    compact = "".join(str(text).split())
    if (
        not compact
        or len(compact) % 2
        or any(c not in "0123456789abcdefABCDEF" for c in compact)
    ):
        raise TargetError(f"{what}: must be a non-empty, even-length hex byte string")
    return bytes.fromhex(compact)


def field_str(mapping: dict, key: str, where: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise TargetError(f"{where}: {key!r} must be a non-empty string")
    return value


def field_int(mapping: dict, key: str, where: str) -> int:
    value = mapping.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise TargetError(f"{where}: {key!r} must be an integer")
    return value


def field_address(mapping: dict, key: str, where: str) -> int:
    value = mapping.get(key)
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise TargetError(
            f"{where}: {key!r} must be an address string such as \"0x00000000\""
        )
    return parse_number(value, f"{where}: {key}")


def load_target(directory: str | Path) -> Target:
    """Load and fully verify a target directory, or raise TargetError."""
    directory = Path(directory)
    manifest_path = directory / MANIFEST_NAME
    manifest = load_json(manifest_path)
    where = str(manifest_path)
    if not isinstance(manifest, dict):
        raise TargetError(f"{where}: expected a JSON object")

    schema = field_int(manifest, "schema_version", where)
    if schema != SUPPORTED_SCHEMA_VERSION:
        raise TargetError(
            f"{where}: unsupported schema_version {schema}"
            f" (this tool supports {SUPPORTED_SCHEMA_VERSION})"
        )
    name = field_str(manifest, "target", where)
    if name != directory.name:
        raise TargetError(
            f"{where}: target {name!r} does not match directory name {directory.name!r}"
        )

    artifact = manifest.get("artifact")
    if not isinstance(artifact, dict):
        raise TargetError(f"{where}: 'artifact' must be a JSON object")
    artifact_where = f"{where}: artifact"
    relative = field_str(artifact, "path", artifact_where)
    if Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise TargetError(
            f"{artifact_where}.path: must stay inside the target directory:"
            f" {relative!r}"
        )
    size = field_int(artifact, "size", artifact_where)
    digest = field_str(artifact, "sha256", artifact_where).lower()
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise TargetError(
            f"{artifact_where}.sha256: expected 64 hexadecimal characters"
        )
    base = field_address(artifact, "base_address", artifact_where)
    require_aligned(base, f"{artifact_where}.base_address")
    byte_order = field_str(artifact, "byte_order", artifact_where)
    if byte_order != SUPPORTED_BYTE_ORDER:
        raise TargetError(
            f"{artifact_where}.byte_order: unsupported value {byte_order!r}"
            f" (only {SUPPORTED_BYTE_ORDER!r} is implemented)"
        )
    mode = field_str(artifact, "default_mode", artifact_where)
    if mode != SUPPORTED_MODE:
        raise TargetError(
            f"{artifact_where}.default_mode: unsupported value {mode!r}"
            f" (only {SUPPORTED_MODE!r} is established;"
            " Thumb decoding is not attempted)"
        )

    artifact_path = directory / relative
    try:
        data = artifact_path.read_bytes()
    except OSError as exc:
        raise TargetError(
            f"{artifact_where}.path: cannot read {artifact_path}: {exc}"
        ) from None
    if len(data) != size:
        raise TargetError(
            f"{artifact_where}.size: manifest says {size} bytes, {artifact_path} has"
            f" {len(data)} bytes (truncated or wrong artifact?)"
        )
    actual = hashlib.sha256(data).hexdigest()
    if actual != digest:
        raise TargetError(
            f"{artifact_where}.sha256: manifest {digest}, {artifact_path} {actual}"
            " (stale manifest or wrong artifact?)"
        )

    symbols = load_symbols(directory / SYMBOLS_NAME, name, data, base)
    return Target(
        directory=directory,
        manifest_path=manifest_path,
        manifest=manifest,
        artifact_path=artifact_path,
        data=data,
        base=base,
        symbols=symbols,
    )


def load_symbols(
    path: Path, target_name: str, data: bytes, base: int
) -> tuple[Symbol, ...]:
    """Load the symbol map and check every annotation against the ROM bytes."""
    document = load_json(path)
    where = str(path)
    if not isinstance(document, dict):
        raise TargetError(f"{where}: expected a JSON object")
    schema = field_int(document, "schema_version", where)
    if schema != SUPPORTED_SCHEMA_VERSION:
        raise TargetError(
            f"{where}: unsupported schema_version {schema}"
            f" (this tool supports {SUPPORTED_SCHEMA_VERSION})"
        )
    document_target = field_str(document, "target", where)
    if document_target != target_name:
        raise TargetError(
            f"{where}: target {document_target!r} does not match manifest target"
            f" {target_name!r}"
        )
    entries = document.get("symbols")
    if not isinstance(entries, list):
        raise TargetError(f"{where}: 'symbols' must be a JSON array")

    symbols = []
    by_address: dict[int, Symbol] = {}
    by_name: dict[str, Symbol] = {}
    for index, entry in enumerate(entries):
        symbol = parse_symbol(entry, index, where, data, base)
        if symbol.address in by_address:
            raise TargetError(
                f"{where}: duplicate address 0x{symbol.address:08x}"
                f" ({by_address[symbol.address].name!r} and {symbol.name!r})"
            )
        if symbol.name in by_name:
            raise TargetError(f"{where}: duplicate symbol name {symbol.name!r}")
        by_address[symbol.address] = symbol
        by_name[symbol.name] = symbol
        symbols.append(symbol)
    return tuple(symbols)


def parse_symbol(
    entry: object, index: int, where: str, data: bytes, base: int
) -> Symbol:
    if not isinstance(entry, dict):
        raise TargetError(f"{where}: symbol #{index}: must be a JSON object")
    name = field_str(entry, "name", f"{where}: symbol #{index}")
    label = f"{where}: symbol {name!r}"
    if any(c.isspace() for c in name):
        raise TargetError(f"{label}: name must not contain whitespace")

    address = field_address(entry, "address", label)
    if not base <= address < base + len(data):
        raise TargetError(
            f"{label}: address 0x{address:08x} is outside the artifact range"
            f" 0x{base:08x}..0x{base + len(data):08x} (stale symbol map?)"
        )
    kind = field_str(entry, "kind", label)
    if kind not in SYMBOL_KINDS:
        raise TargetError(
            f"{label}: kind {kind!r} is not one of {', '.join(SYMBOL_KINDS)}"
        )
    confidence = field_str(entry, "confidence", label)
    if confidence not in SYMBOL_CONFIDENCES:
        raise TargetError(
            f"{label}: confidence {confidence!r} is not one of"
            f" {', '.join(SYMBOL_CONFIDENCES)}"
        )
    if kind in ("function", "label") and (address - base) % ARM_INSN_SIZE:
        raise TargetError(
            f"{label}: {kind} address 0x{address:08x} is not {ARM_INSN_SIZE}-byte"
            " aligned (use kind 'data' for unaligned data)"
        )
    summary = entry.get("summary", "")
    if not isinstance(summary, str):
        raise TargetError(f"{label}: 'summary' must be a string when present")
    if any(c in summary for c in "\t\r\n"):
        raise TargetError(f"{label}: 'summary' must be a single line without tabs")

    evidence_entries = entry.get("evidence")
    if not isinstance(evidence_entries, list) or not evidence_entries:
        raise TargetError(
            f"{label}: 'evidence' must be a non-empty JSON array"
            " (every symbol needs a byte-level anchor)"
        )
    evidence = tuple(
        parse_evidence(item, i, label, data, base)
        for i, item in enumerate(evidence_entries)
    )
    return Symbol(
        address=address,
        name=name,
        kind=kind,
        confidence=confidence,
        summary=summary,
        evidence=evidence,
    )


def parse_evidence(
    item: object, index: int, label: str, data: bytes, base: int
) -> Evidence:
    where = f"{label} evidence #{index}"
    if not isinstance(item, dict):
        raise TargetError(f"{where}: must be a JSON object")
    address = field_address(item, "address", where)
    expected = parse_hex_bytes(field_str(item, "bytes", where), where)
    note = item.get("note", "")
    if not isinstance(note, str):
        raise TargetError(f"{where}: 'note' must be a string when present")

    offset = address - base
    if offset < 0 or offset + len(expected) > len(data):
        raise TargetError(
            f"{where}: 0x{address:08x} + {len(expected)} bytes is outside the artifact"
            f" range 0x{base:08x}..0x{base + len(data):08x}"
        )
    actual = data[offset:offset + len(expected)]
    if actual != expected:
        raise TargetError(
            f"{where}: bytes {expected.hex()} do not match ROM bytes {actual.hex()}"
            f" at 0x{address:08x} (stale anchor or wrong artifact revision?)"
        )
    return Evidence(address=address, data=expected, note=note)


def symbol_descriptor(symbol: Symbol) -> str:
    return f"{symbol.name} ({symbol.kind}, {symbol.confidence})"


def matching_symbol(symbols: dict[int, Symbol], value: int) -> Symbol | None:
    """Find a numeric match, not proof of a pointer; omit ubiquitous zeros."""
    if value == 0:
        return None
    return symbols.get(value)


def target_identity(target: Target) -> str:
    return (
        f"target {target.name}  artifact {target.artifact_name}"
        f"  sha256 {target.sha256}  base 0x{target.base:08x}"
    )


def format_row(address: int, body: str, note: str = "") -> str:
    row = f"0x{address:08x}  {body}"
    if note:
        row = f"{row:<{NOTE_COLUMN}} ; {note}"
    return row


def pc_relative_literal(insn, target: Target) -> tuple[int, int | None] | None:
    """Literal address (and value when readable) of a PC-relative load."""
    width = LITERAL_LOAD_WIDTHS.get(insn.id)
    if width is None or len(insn.operands) < 2:
        return None
    operand = insn.operands[1]
    if operand.type != ARM_OP_MEM:
        return None
    if operand.mem.base != ARM_REG_PC or operand.mem.index:
        return None
    address = insn.address + ARM_PC_BIAS + operand.mem.disp
    if not target.contains(address, width):
        return address, None
    offset = address - target.base
    return address, int.from_bytes(target.data[offset:offset + width], "little")


def instruction_annotation(insn, target: Target, symbols: dict[int, Symbol]) -> str:
    notes = []
    symbol = symbols.get(insn.address)
    if symbol is not None:
        notes.append(symbol_descriptor(symbol))

    literal = pc_relative_literal(insn, target)
    if literal is not None:
        address, value = literal
        if value is None:
            notes.append(f"literal 0x{address:08x} (outside artifact)")
        else:
            text = f"literal 0x{address:08x} = 0x{value:x}"
            matched = matching_symbol(symbols, value)
            if matched is not None:
                text += f"; value matches {symbol_descriptor(matched)}"
            notes.append(text)

    if (
        (ARM_GRP_JUMP in insn.groups or CS_GRP_CALL in insn.groups)
        and insn.operands
        and insn.operands[0].type == ARM_OP_IMM
    ):
        pointed = symbols.get(insn.operands[0].imm)
        if pointed is not None:
            notes.append(f"-> {symbol_descriptor(pointed)}")
    return "; ".join(notes)


def disassemble(target: Target, start: int, length: int) -> list[str]:
    """Linear ARM listing of an aligned range; undecodable words are explicit."""
    decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    symbols = target.symbol_index()
    lines = []
    for address in range(start, start + length, ARM_INSN_SIZE):
        offset = address - target.base
        chunk = target.data[offset:offset + ARM_INSN_SIZE]
        insn = next(iter(decoder.disasm(chunk, address)), None)
        if insn is None:
            lines.append(
                format_row(
                    address,
                    f"{chunk.hex():<8}  <invalid>",
                    "not a decodable ARM instruction",
                )
            )
            continue
        operands = f"{insn.mnemonic:<9} {insn.op_str}".rstrip()
        lines.append(
            format_row(
                address,
                f"{insn.bytes.hex():<8}  {operands}",
                instruction_annotation(insn, target, symbols),
            )
        )
    return lines


def printable_runs(data: bytes, min_length: int) -> list[tuple[int, str]]:
    """Printable ASCII runs of at least min_length bytes, as (offset, text)."""
    runs = []
    start = None
    for index, byte in enumerate(data):
        if 0x20 <= byte <= 0x7E:
            if start is None:
                start = index
        else:
            if start is not None and index - start >= min_length:
                runs.append((start, data[start:index].decode("ascii")))
            start = None
    if start is not None and len(data) - start >= min_length:
        runs.append((start, data[start:].decode("ascii")))
    return runs


def cmd_verify(target: Target, args: argparse.Namespace) -> int:
    anchors = sum(len(symbol.evidence) for symbol in target.symbols)
    print(f"target:    {target.name}")
    print(
        f"manifest:  {target.manifest_path}"
        f" (schema_version {SUPPORTED_SCHEMA_VERSION})"
    )
    print(f"artifact:  {target.artifact_path}")
    print(f"size:      {target.size} bytes (0x{target.size:08x}); matches manifest")
    print(f"sha256:    {target.sha256}; matches manifest")
    print(f"base:      0x{target.base:08x}")
    print(f"mode:      {SUPPORTED_MODE}, {SUPPORTED_BYTE_ORDER}-endian")
    print(
        f"symbols:   {target.symbols_path}: {len(target.symbols)} symbols,"
        f" {anchors} evidence anchors, all match ROM"
    )
    print(
        "identity:  directory name, manifest target and symbols.json target"
        " all agree"
    )
    print("verify:    OK")
    return 0


def cmd_disasm(target: Target, args: argparse.Namespace) -> int:
    start = parse_number(args.start, "START")
    length = parse_number(args.length, "LENGTH")
    require_aligned(start, "START")
    require_aligned(length, "LENGTH")
    if length == 0:
        raise TargetError("LENGTH: must be a positive multiple of 4")
    if not target.contains(start, length):
        raise TargetError(
            f"range 0x{start:08x}..0x{start + length:08x} is outside the artifact range"
            f" 0x{target.base:08x}..0x{target.end:08x}"
        )
    print(f"; {target_identity(target)}")
    print(
        f"; bounded linear ARM disassembly 0x{start:08x}..0x{start + length:08x}"
        f" ({length} bytes); not a function or control-flow analysis"
    )
    for line in disassemble(target, start, length):
        print(line)
    return 0


def cmd_words(target: Target, args: argparse.Namespace) -> int:
    start = parse_number(args.start, "START")
    count = parse_number(args.count, "COUNT")
    require_aligned(start, "START")
    if count == 0:
        raise TargetError("COUNT: must be at least 1")
    length = count * ARM_INSN_SIZE
    if not target.contains(start, length):
        raise TargetError(
            f"range 0x{start:08x}..0x{start + length:08x} is outside the artifact range"
            f" 0x{target.base:08x}..0x{target.end:08x}"
        )
    print(f"; {target_identity(target)}")
    print(
        f"; little-endian u32 words 0x{start:08x}..0x{start + length:08x}"
        f" ({count} words); numeric symbol matches do not establish pointers"
    )
    symbols = target.symbol_index()
    for address in range(start, start + length, ARM_INSN_SIZE):
        offset = address - target.base
        value = int.from_bytes(target.data[offset:offset + ARM_INSN_SIZE], "little")
        note = ""
        matched = matching_symbol(symbols, value)
        if matched is not None:
            note = f"value matches {symbol_descriptor(matched)}"
        print(format_row(address, f"0x{value:08x}", note))
    return 0


def cmd_strings(target: Target, args: argparse.Namespace) -> int:
    if args.min_length < 1:
        raise TargetError("--min-length: must be at least 1")
    print(f"; {target_identity(target)}")
    print(
        f"; printable ASCII runs of {args.min_length} bytes or more"
        " (addresses are ROM addresses, not file offsets)"
    )
    for offset, text in printable_runs(target.data, args.min_length):
        print(f"0x{target.base + offset:08x}  {text}")
    return 0


def cmd_symbols(target: Target, args: argparse.Namespace) -> int:
    print("# bootromancy symbol map")
    print(f"# {target_identity(target)}")
    print("# address\tname\tkind\tconfidence\tsummary")
    for symbol in sorted(target.symbols, key=lambda s: s.address):
        print(
            f"0x{symbol.address:08x}\t{symbol.name}\t{symbol.kind}"
            f"\t{symbol.confidence}\t{symbol.summary}"
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rom.py",
        description="Offline inspection of Bootromancy ROM targets.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    verify = commands.add_parser(
        "verify", help="verify manifest, artifact size/hash and symbol anchors"
    )
    verify.add_argument("target", metavar="TARGET_DIRECTORY")
    verify.set_defaults(func=cmd_verify)

    disasm = commands.add_parser(
        "disasm", help="bounded linear ARM disassembly of START..START+LENGTH"
    )
    disasm.add_argument("target", metavar="TARGET_DIRECTORY")
    disasm.add_argument(
        "start", metavar="START", help="first address (decimal or 0x hex)"
    )
    disasm.add_argument("length", metavar="LENGTH", help="byte count (multiple of 4)")
    disasm.set_defaults(func=cmd_disasm)

    words = commands.add_parser(
        "words", help="little-endian u32 values at START..START+4*COUNT"
    )
    words.add_argument("target", metavar="TARGET_DIRECTORY")
    words.add_argument(
        "start", metavar="START", help="first address (decimal or 0x hex)"
    )
    words.add_argument("count", metavar="COUNT", help="number of 4-byte words")
    words.set_defaults(func=cmd_words)

    strings = commands.add_parser(
        "strings", help="printable ASCII runs at their ROM addresses"
    )
    strings.add_argument("target", metavar="TARGET_DIRECTORY")
    strings.add_argument(
        "--min-length",
        type=int,
        default=DEFAULT_MIN_STRING_LENGTH,
        metavar="N",
        help=f"minimum run length in bytes (default {DEFAULT_MIN_STRING_LENGTH})",
    )
    strings.set_defaults(func=cmd_strings)

    symbols = commands.add_parser(
        "symbols", help="tab-separated symbol map for import and review"
    )
    symbols.add_argument("target", metavar="TARGET_DIRECTORY")
    symbols.set_defaults(func=cmd_symbols)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        target = load_target(args.target)
        return args.func(target, args)
    except TargetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
