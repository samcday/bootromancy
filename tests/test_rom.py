"""Focused tests for tools/rom.py.

Run from the repository root:

    python3 -m unittest discover -s tests -v

The synthetic fixture below is a deliberately tiny ARM image, so decoder and
annotation behaviour is pinned independently of the real PBL. The real target
under targets/ is checked for integrity separately, but only for the symbols
and annotations guaranteed by the current contract.
"""

import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

import rom  # noqa: E402  (tools/ is added to sys.path above)

REAL_TARGET = REPO_ROOT / "targets" / "msm8930-r1.2"


def fixture_blob() -> bytes:
    """256-byte synthetic ARM image used by most tests.

    0x00  b #0x20            (symbol reset_vector)
    0x04  b #0x10            (target has no symbol)
    0x08  0xffffffff         (does not decode as ARM)
    0x0c  mov r0, r0
    0x10  ldr r0, [pc, #4]   (literal at 0x1c)
    0x14  msr cpsr_c, #0xd1
    0x18  bx lr
    0x1c  0x9abcdef0         (literal value)
    0x20  mov r0, r0         (symbol entry_point)
    0x24  ldr r0, [pc, #4]   (literal at 0x30 numerically matches entry_point)
    0x30  0x00000020
    0x40  "HELLO WORLD"
    0x50  "AB"               (too short for the default --min-length)
    """
    blob = bytearray(0x100)
    blob[0x00:0x04] = bytes.fromhex("060000ea")
    blob[0x04:0x08] = bytes.fromhex("010000ea")
    blob[0x08:0x0C] = bytes.fromhex("ffffffff")
    blob[0x0C:0x10] = bytes.fromhex("0000a0e1")
    blob[0x10:0x14] = bytes.fromhex("04009fe5")
    blob[0x14:0x18] = bytes.fromhex("d1f021e3")
    blob[0x18:0x1C] = bytes.fromhex("1eff2fe1")
    blob[0x1C:0x20] = bytes.fromhex("f0debc9a")
    blob[0x20:0x24] = bytes.fromhex("0000a0e1")
    blob[0x24:0x28] = bytes.fromhex("04009fe5")
    blob[0x30:0x34] = (0x20).to_bytes(4, "little")
    blob[0x40:0x4B] = b"HELLO WORLD"
    blob[0x50:0x52] = b"AB"
    return bytes(blob)


def fixture_symbols(target_name: str) -> dict:
    return {
        "schema_version": 1,
        "target": target_name,
        "name_origin": "analyst",
        "symbols": [
            {
                "address": "0x00000000",
                "name": "reset_vector",
                "kind": "label",
                "confidence": "observed",
                "summary": "Reset vector branches to entry_point.",
                "evidence": [
                    {
                        "address": "0x00000000",
                        "bytes": "060000ea",
                        "note": "EA000006 decodes as ARM b #0x20.",
                    }
                ],
            },
            {
                "address": "0x00000020",
                "name": "entry_point",
                "kind": "function",
                "confidence": "inferred",
                "summary": "Fixture entry point.",
                "evidence": [{"address": "0x00000020", "bytes": "0000a0e1"}],
            },
            {
                "address": "0x0000001c",
                "name": "fixture_literal",
                "kind": "data",
                "confidence": "candidate",
                "summary": "Fixture literal word.",
                "evidence": [{"address": "0x0000001c", "bytes": "f0debc9a"}],
            },
        ],
    }


def shifted_symbols(target_name: str, shift: int) -> dict:
    """fixture_symbols() with every address (symbol and evidence) shifted."""
    symbols = fixture_symbols(target_name)
    for symbol in symbols["symbols"]:
        symbol["address"] = hex(int(symbol["address"], 16) + shift)
        for evidence in symbol["evidence"]:
            evidence["address"] = hex(int(evidence["address"], 16) + shift)
    return symbols


class Fixture:
    """A synthetic target directory whose documents stay mutable for tampering."""

    def __init__(
        self, directory: Path, name: str | None = None, blob=None, symbols=None
    ):
        self.directory = directory
        self.name = name or directory.name
        self.blob = fixture_blob() if blob is None else blob
        self.manifest = {
            "schema_version": 1,
            "target": self.name,
            "artifact": {
                "path": "rom.bin",
                "size": len(self.blob),
                "sha256": hashlib.sha256(self.blob).hexdigest(),
                "base_address": "0x00000000",
                "byte_order": "little",
                "default_mode": "arm",
            },
        }
        self.symbols = fixture_symbols(self.name) if symbols is None else symbols

    def write(self) -> Path:
        self.directory.mkdir(parents=True, exist_ok=True)
        (self.directory / "rom.bin").write_bytes(self.blob)
        self.write_manifest()
        self.write_symbols()
        return self.directory

    def write_manifest(self) -> None:
        (self.directory / "manifest.json").write_text(
            json.dumps(self.manifest, indent=2)
        )

    def write_symbols(self) -> None:
        (self.directory / "symbols.json").write_text(json.dumps(self.symbols, indent=2))


def run_cli(*argv: str) -> tuple[int, str, str]:
    """Run rom.main() with captured streams; returns (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = rom.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class RomTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    def make_target(self, directory_name="test-target", **kwargs) -> Fixture:
        fixture = Fixture(self.tmp / directory_name, **kwargs)
        fixture.write()
        return fixture

    def assert_rejected(self, fixture, pattern, *argv):
        """Every command must reject an untrustworthy target, not print from it.

        argv is the command and its options; the target directory always
        follows the command name on the real command line.
        """
        code, out, err = run_cli(argv[0], str(fixture.directory), *argv[1:])
        self.assertEqual(code, 1)
        self.assertEqual(out, "")
        self.assertRegex(err, pattern)
        return err


class NumberParsingTests(unittest.TestCase):
    def test_decimal_and_hex(self):
        self.assertEqual(rom.parse_number("32", "X"), 32)
        self.assertEqual(rom.parse_number("0x20", "X"), 32)
        self.assertEqual(rom.parse_number("0X20", "X"), 32)
        self.assertEqual(rom.parse_number(32, "X"), 32)

    def test_rejects_non_numbers_and_negatives(self):
        for text in ("", "zz", "0xzz", "1.5", "-4"):
            with self.subTest(text=text):
                with self.assertRaisesRegex(rom.TargetError, "X"):
                    rom.parse_number(text, "X")


class ManifestTests(RomTestCase):
    def test_verify_accepts_fixture(self):
        fixture = self.make_target()
        code, out, err = run_cli("verify", str(fixture.directory))
        self.assertEqual((code, err), (0, ""))
        self.assertIn("verify:    OK", out)
        self.assertIn(f"target:    {fixture.name}", out)
        self.assertIn("sha256:", out)

    def test_missing_manifest(self):
        code, out, err = run_cli("verify", str(self.tmp / "nothing-here"))
        self.assertEqual(code, 1)
        self.assertIn("manifest.json", err)

    def test_invalid_json(self):
        fixture = self.make_target()
        (fixture.directory / "manifest.json").write_text("{not json")
        self.assert_rejected(fixture, "invalid JSON", "verify")

    def test_unsupported_schema_version(self):
        fixture = self.make_target()
        fixture.manifest["schema_version"] = 2
        fixture.write_manifest()
        self.assert_rejected(fixture, "schema_version 2", "verify")

    def test_target_must_match_directory_name(self):
        fixture = self.make_target()
        fixture.manifest["target"] = "somewhere-else"
        fixture.write_manifest()
        self.assert_rejected(fixture, "does not match directory name", "verify")

    def test_hash_mismatch_is_rejected(self):
        fixture = self.make_target()
        fixture.manifest["artifact"]["sha256"] = "0" * 64
        fixture.write_manifest()
        err = self.assert_rejected(fixture, "sha256", "verify")
        self.assertIn("stale manifest or wrong artifact", err)

    def test_same_size_wrong_revision_is_rejected(self):
        fixture = self.make_target()
        blob = bytearray(fixture.blob)
        blob[0x0C] ^= 0xFF
        (fixture.directory / "rom.bin").write_bytes(bytes(blob))
        self.assert_rejected(fixture, "sha256", "verify")

    def test_truncated_blob_is_rejected(self):
        fixture = self.make_target()
        (fixture.directory / "rom.bin").write_bytes(fixture.blob[:128])
        self.assert_rejected(fixture, "size", "verify")

    def test_missing_artifact_is_rejected(self):
        fixture = self.make_target()
        (fixture.directory / "rom.bin").unlink()
        self.assert_rejected(fixture, "cannot read", "verify")

    def test_byte_order_must_be_little(self):
        fixture = self.make_target()
        fixture.manifest["artifact"]["byte_order"] = "big"
        fixture.write_manifest()
        self.assert_rejected(fixture, "byte_order", "verify")

    def test_default_mode_must_be_arm(self):
        fixture = self.make_target()
        fixture.manifest["artifact"]["default_mode"] = "thumb"
        fixture.write_manifest()
        self.assert_rejected(fixture, "default_mode.*Thumb", "verify")

    def test_artifact_path_must_stay_in_target(self):
        fixture = self.make_target()
        fixture.manifest["artifact"]["path"] = "../rom.bin"
        fixture.write_manifest()
        self.assert_rejected(fixture, "must stay inside the target directory", "verify")

    def test_extra_manifest_fields_are_tolerated(self):
        fixture = self.make_target()
        fixture.manifest["hardware"] = {"soc": "Qualcomm MSM8930", "soc_id": 116}
        fixture.manifest["identification"] = {"boot_rom_version": "2.0"}
        fixture.write_manifest()
        code, out, _ = run_cli("verify", str(fixture.directory))
        self.assertEqual(code, 0)
        self.assertIn("verify:    OK", out)

    def test_missing_symbols_file_is_rejected(self):
        fixture = self.make_target()
        (fixture.directory / "symbols.json").unlink()
        self.assert_rejected(fixture, "symbols.json", "verify")

    def test_base_address_is_honoured(self):
        base = 0x1000
        fixture = self.make_target(
            symbols=shifted_symbols("test-target", base)
        )
        fixture.manifest["artifact"]["base_address"] = hex(base)
        fixture.write_manifest()
        code, out, err = run_cli("disasm", str(fixture.directory), "0x1000", "4")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("0x00001000  060000ea  b", out)
        self.assertIn("reset_vector (label, observed)", out)
        self.assertIn("base 0x00001000", out)
        # The same bytes are not addressable below the manifest base.
        code, _, err = run_cli("disasm", str(fixture.directory), "0", "4")
        self.assertEqual(code, 1)
        self.assertIn("outside the artifact range", err)


class SymbolTests(RomTestCase):
    def test_missing_symbols_target(self):
        fixture = self.make_target()
        fixture.symbols["target"] = "another-target"
        fixture.write_symbols()
        self.assert_rejected(fixture, "does not match manifest target", "verify")

    def test_evidence_bytes_must_match_rom(self):
        fixture = self.make_target()
        fixture.symbols["symbols"][0]["evidence"][0]["bytes"] = "ea000006"
        fixture.write_symbols()
        err = self.assert_rejected(fixture, "do not match ROM bytes", "verify")
        self.assertIn("stale anchor", err)

    def test_evidence_address_must_be_in_range(self):
        fixture = self.make_target()
        fixture.symbols["symbols"][0]["evidence"][0]["address"] = "0x00000100"
        fixture.write_symbols()
        self.assert_rejected(fixture, "outside the artifact range", "verify")

    def test_symbol_address_must_be_in_range(self):
        fixture = self.make_target()
        fixture.symbols["symbols"][1]["address"] = "0x00001000"
        fixture.write_symbols()
        self.assert_rejected(fixture, "outside the artifact range", "verify")

    def test_function_must_be_aligned_but_data_need_not_be(self):
        fixture = self.make_target()
        fixture.symbols["symbols"][1]["address"] = "0x00000022"
        fixture.write_symbols()
        self.assert_rejected(fixture, "not 4-byte aligned", "verify")

        fixture = self.make_target()
        fixture.symbols["symbols"][1]["address"] = "0x00000022"
        fixture.symbols["symbols"][1]["kind"] = "data"
        fixture.symbols["symbols"][1]["evidence"][0]["address"] = "0x00000022"
        fixture.symbols["symbols"][1]["evidence"][0]["bytes"] = "a0e1"
        fixture.write_symbols()
        code, out, err = run_cli("verify", str(fixture.directory))
        self.assertEqual((code, err), (0, ""))
        self.assertIn("verify:    OK", out)

    def test_duplicate_addresses_and_names_are_rejected(self):
        fixture = self.make_target()
        fixture.symbols["symbols"][1]["address"] = "0x00000000"
        fixture.write_symbols()
        self.assert_rejected(fixture, "duplicate address", "verify")

        fixture = self.make_target()
        fixture.symbols["symbols"][1]["name"] = "reset_vector"
        fixture.write_symbols()
        self.assert_rejected(fixture, "duplicate symbol name", "verify")

    def test_kind_and_confidence_are_enumerated(self):
        fixture = self.make_target()
        fixture.symbols["symbols"][0]["kind"] = "symbol"
        fixture.write_symbols()
        self.assert_rejected(fixture, "kind 'symbol'", "verify")

        fixture = self.make_target()
        fixture.symbols["symbols"][0]["confidence"] = "guess"
        fixture.write_symbols()
        self.assert_rejected(fixture, "confidence 'guess'", "verify")

    def test_empty_evidence_is_rejected(self):
        fixture = self.make_target()
        fixture.symbols["symbols"][0]["evidence"] = []
        fixture.write_symbols()
        self.assert_rejected(fixture, "non-empty JSON array", "verify")

    def test_extra_symbol_fields_are_tolerated(self):
        fixture = self.make_target()
        symbol = fixture.symbols["symbols"][0]
        symbol["aliases"] = ["vector_table"]
        symbol["reviewed_by"] = "sam"
        symbol["evidence"][0]["tags"] = ["vector"]
        fixture.write_symbols()
        code, out, _ = run_cli("verify", str(fixture.directory))
        self.assertEqual(code, 0)
        self.assertIn("3 symbols, 3 evidence anchors", out)

    def test_summary_must_not_break_the_tsv(self):
        fixture = self.make_target()
        fixture.symbols["symbols"][0]["summary"] = "two\tcolumns"
        fixture.write_symbols()
        self.assert_rejected(fixture, "single line without tabs", "verify")

    def test_every_command_reverifies_before_output(self):
        fixture = self.make_target()
        blob = bytearray(fixture.blob)
        blob[0x30] = 0x21
        (fixture.directory / "rom.bin").write_bytes(bytes(blob))
        for argv in (
            ("disasm", "0", "4"),
            ("words", "0", "1"),
            ("strings",),
            ("symbols",),
        ):
            with self.subTest(command=argv[0]):
                self.assert_rejected(fixture, "sha256", *argv)


class DisasmTests(RomTestCase):
    def test_reset_branch_and_labels(self):
        fixture = self.make_target()
        code, out, err = run_cli("disasm", str(fixture.directory), "0", "8")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("bounded linear ARM disassembly 0x00000000..0x00000008", out)
        self.assertRegex(out, r"0x00000000  060000ea  b\s+#0x20")
        self.assertIn("reset_vector (label, observed)", out)
        self.assertIn("-> entry_point (function, inferred)", out)
        # The second vector branches to an address without a symbol: no invention.
        second = [line for line in out.splitlines() if line.startswith("0x00000004")][0]
        self.assertNotIn("->", second)

    def test_pc_relative_literals_are_annotated(self):
        fixture = self.make_target()
        code, out, _ = run_cli("disasm", str(fixture.directory), "0x10", "0x18")
        self.assertEqual(code, 0)
        self.assertIn("literal 0x0000001c = 0x9abcdef0", out)
        self.assertIn(
            "literal 0x00000030 = 0x20; value matches entry_point (function, inferred)", out
        )

    def test_direct_call_target_is_annotated(self):
        blob = bytearray(fixture_blob())
        blob[4:8] = bytes.fromhex("050000eb")  # BL 0x20 from address 4.
        fixture = self.make_target(blob=bytes(blob))
        code, out, _ = run_cli("disasm", str(fixture.directory), "4", "4")
        self.assertEqual(code, 0)
        self.assertIn("bl", out)
        self.assertIn("-> entry_point (function, inferred)", out)

    def test_invalid_instruction_is_explicit_and_linear(self):
        fixture = self.make_target()
        code, out, _ = run_cli("disasm", str(fixture.directory), "0", "0x20")
        self.assertEqual(code, 0)
        self.assertIn("0x00000008  ffffffff  <invalid>", out)
        self.assertIn("not a decodable ARM instruction", out)
        # Decoding continues after the invalid word.
        self.assertIn("0x0000000c  0000a0e1  mov", out)
        self.assertIn("0x00000018  1eff2fe1  bx", out)

    def test_thumb_bytes_are_not_decoded_as_thumb(self):
        empty = {"schema_version": 1, "target": "test-target", "symbols": []}
        # 0xbf00 0xbf00 is two Thumb nops; as an ARM word it is svclt #0xbf00.
        fixture = self.make_target(blob=bytes.fromhex("00bf00bf"), symbols=empty)
        code, out, _ = run_cli("disasm", str(fixture.directory), "0", "4")
        self.assertEqual(code, 0)
        self.assertIn("svclt", out)
        self.assertNotIn("nop", out)

    def test_alignment_and_range_are_enforced(self):
        fixture = self.make_target()
        for start, length, pattern in (
            ("2", "4", "START.*not 4-byte aligned"),
            ("0", "6", "LENGTH.*not 4-byte aligned"),
            ("0", "0", "positive multiple of 4"),
            ("0x100", "4", "outside the artifact range"),
            ("0xf8", "0x10", "outside the artifact range"),
        ):
            with self.subTest(start=start, length=length):
                code, out, err = run_cli(
                    "disasm", str(fixture.directory), start, length
                )
                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertRegex(err, pattern)

    def test_no_whole_rom_output_is_implied(self):
        fixture = self.make_target()
        code, out, _ = run_cli("disasm", str(fixture.directory), "0", "4")
        self.assertEqual(code, 0)
        rows = [line for line in out.splitlines() if line.startswith("0x")]
        self.assertEqual(len(rows), 1)


class WordTests(RomTestCase):
    def test_little_endian_values(self):
        empty = {"schema_version": 1, "target": "test-target", "symbols": []}
        fixture = self.make_target(
            blob=bytes.fromhex("01020304") + b"\x00" * 12, symbols=empty
        )
        code, out, _ = run_cli("words", str(fixture.directory), "0", "1")
        self.assertEqual(code, 0)
        self.assertIn("0x00000000  0x04030201", out)

    def test_numeric_symbol_match_is_labelled(self):
        fixture = self.make_target()
        # Matching a symbol address does not establish the word's type.
        code, out, _ = run_cli("words", str(fixture.directory), "0x30", "1")
        self.assertEqual(code, 0)
        self.assertIn("0x00000030  0x00000020", out)
        self.assertIn("value matches entry_point (function, inferred)", out)
        self.assertNotIn("->", out)

    def test_null_word_is_not_a_pointer(self):
        fixture = self.make_target()
        code, out, _ = run_cli("words", str(fixture.directory), "0x28", "1")
        self.assertEqual(code, 0)
        line = [line for line in out.splitlines() if line.startswith("0x00000028")][0]
        self.assertNotIn("->", line)

    def test_alignment_count_and_range(self):
        fixture = self.make_target()
        for argv, pattern in (
            (("2", "1"), "START.*not 4-byte aligned"),
            (("0", "0"), "COUNT.*at least 1"),
            (("0xfc", "4"), "outside the artifact range"),
        ):
            with self.subTest(argv=argv):
                code, out, err = run_cli("words", str(fixture.directory), *argv)
                self.assertEqual(code, 1)
                self.assertEqual(out, "")
                self.assertRegex(err, pattern)


class StringsTests(RomTestCase):
    def test_printable_runs_with_addresses(self):
        fixture = self.make_target()
        code, out, err = run_cli("strings", str(fixture.directory))
        self.assertEqual((code, err), (0, ""))
        self.assertIn("0x00000040  HELLO WORLD", out)
        self.assertNotIn("0x00000050", out)

    def test_min_length(self):
        fixture = self.make_target()
        code, out, _ = run_cli("strings", str(fixture.directory), "--min-length", "2")
        self.assertEqual(code, 0)
        self.assertIn("0x00000050  AB", out)

        code, _, err = run_cli("strings", str(fixture.directory), "--min-length", "0")
        self.assertEqual(code, 1)
        self.assertIn("at least 1", err)


class SymbolMapTests(RomTestCase):
    def test_tab_separated_and_sorted_by_address(self):
        fixture = self.make_target()
        code, out, err = run_cli("symbols", str(fixture.directory))
        self.assertEqual((code, err), (0, ""))
        self.assertIn("# address\tname\tkind\tconfidence\tsummary", out)
        rows = [line for line in out.splitlines() if not line.startswith("#")]
        self.assertEqual(len(rows), 3)
        addresses = [int(row.split("\t")[0], 16) for row in rows]
        self.assertEqual(addresses, sorted(addresses))
        first = rows[0].split("\t")
        self.assertEqual(first[:4], ["0x00000000", "reset_vector", "label", "observed"])
        self.assertEqual(first[4], "Reset vector branches to entry_point.")

    def test_header_identifies_artifact(self):
        fixture = self.make_target()
        _, out, _ = run_cli("symbols", str(fixture.directory))
        self.assertIn(f"target {fixture.name}", out)
        self.assertIn("artifact rom.bin", out)
        self.assertIn(fixture.manifest["artifact"]["sha256"], out)


class RealTargetTests(unittest.TestCase):
    """Integrity of the committed target; must not assume a symbol count."""

    def setUp(self):
        if not (REAL_TARGET / "manifest.json").exists():
            self.skipTest(f"{REAL_TARGET} is not present")

    def test_verify(self):
        code, out, err = run_cli("verify", str(REAL_TARGET))
        self.assertEqual((code, err), (0, ""))
        self.assertIn("target:    msm8930-r1.2", out)
        self.assertIn("verify:    OK", out)

    def test_artifact_hash_round_trip(self):
        target = rom.load_target(REAL_TARGET)
        digest = hashlib.sha256((REAL_TARGET / "pbl.bin").read_bytes()).hexdigest()
        self.assertEqual(target.sha256, digest)
        self.assertEqual(target.size, 0x20000)
        self.assertEqual(target.base, 0)

    def test_reset_entry_symbol_is_present(self):
        target = rom.load_target(REAL_TARGET)
        symbols = target.symbol_index()
        self.assertIn(0x20, symbols)
        self.assertEqual(symbols[0x20].kind, "function")
        self.assertIn(0x0, symbols)

    def test_reset_branch_annotated(self):
        code, out, err = run_cli("disasm", str(REAL_TARGET), "0", "8")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("0x00000000  060000ea  b", out)
        self.assertIn("-> reset_entry (function, observed)", out)

    def test_reset_entry_instruction(self):
        code, out, _ = run_cli("disasm", str(REAL_TARGET), "0x20", "4")
        self.assertEqual(code, 0)
        self.assertIn("0x00000020  d1f021e3  msr", out)
        self.assertIn("reset_entry", out)

    def test_pc_literal_from_reset_entry(self):
        code, out, _ = run_cli("disasm", str(REAL_TARGET), "0x34", "4")
        self.assertEqual(code, 0)
        self.assertIn("ldr", out)
        self.assertIn("literal 0x00000324 = 0x902ba4", out)

    def test_words_decode_little_endian_values(self):
        code, out, _ = run_cli("words", str(REAL_TARGET), "0", "2")
        self.assertEqual(code, 0)
        self.assertIn("0x00000000  0xea000006", out)
        self.assertIn("0x00000004  0xea000060", out)

    def test_copy_length_is_not_misclassified_as_a_pointer(self):
        # 0x11f44 is a byte count of 0x20, not a pointer to reset_entry.
        code, out, _ = run_cli("words", str(REAL_TARGET), "0x11f44", "1")
        self.assertEqual(code, 0)
        self.assertIn("0x00011f44  0x00000020", out)
        self.assertIn("value matches reset_entry (function, observed)", out)
        self.assertNotIn("->", out)

    def test_symbol_map_rows(self):
        code, out, _ = run_cli("symbols", str(REAL_TARGET))
        self.assertEqual(code, 0)
        rows = [line for line in out.splitlines() if not line.startswith("#")]
        self.assertGreaterEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(len(row.split("\t")), 5)
        self.assertIn("0x00000000\treset_vector\tlabel\tobserved\t", out)
        self.assertIn("0x00000020\treset_entry\tfunction\tobserved\t", out)

    def test_notice_string_is_findable(self):
        code, out, _ = run_cli("strings", str(REAL_TARGET))
        self.assertEqual(code, 0)
        self.assertIn("0x00011fe0  QUALCOMM COPYRIGHT 2011", out)


class EntryPointTests(unittest.TestCase):
    """The documented command line, exercised as a real process."""

    def run_script(self, *argv):
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "tools" / "rom.py"), *argv],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )

    def test_script_entry_point(self):
        if not (REAL_TARGET / "manifest.json").exists():
            self.skipTest(f"{REAL_TARGET} is not present")
        result = self.run_script("verify", str(REAL_TARGET))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("verify:    OK", result.stdout)

    def test_script_entry_point_failure(self):
        result = self.run_script("verify", str(REAL_TARGET / "does-not-exist"))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("error:", result.stderr)


if __name__ == "__main__":
    unittest.main()
