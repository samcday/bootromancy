# Bootromancy

An evidence-backed atlas of Qualcomm boot ROMs, starting with MSM8930.

The name can be occult. The annotations cannot.

## Start here

| Target | Artifact | Current map |
|---|---|---|
| [MSM8930 revision 1.2](targets/msm8930-r1.2/manifest.json) | Original 128 KiB PBL window, linked at zero; BOOT ROM 2.0 | [Reset → boot main → image loading/authentication → SBL handoff](targets/msm8930-r1.2/boot-flow.md) |

The target came from a Samsung Galaxy Express GT-I8730. It was read through
`/dev/mem` using a RAM-booted Pocketboot diagnostic kernel, without an EDL
programmer or TrustZone exploit. Two complete reads agreed. Acquisition
provenance is in the manifest; detailed evidence lives in Git notes.

This is a static reconstruction, not a trace of which boot path ran on that
phone. It does not establish the handset's fuse values or permit an unsigned
replacement loader. SDCC/SPI/download entrypoints are identified; controller
and USB protocol internals are later passes.

## Reproduce the analysis

Python 3.10+ and the pinned Capstone decoder are sufficient. No device access
or proprietary analysis application is required.

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
make check
make listings
```

`make listings` writes selected annotated instruction windows, table words,
strings and a TSV symbol map beneath `out/msm8930-r1.2/`. Generated listings
are ignored; the ROM, manifest and annotations are the sources of truth.

Individual operations:

```sh
python3 tools/rom.py verify targets/msm8930-r1.2
python3 tools/rom.py disasm targets/msm8930-r1.2 0x6720 0xa0
python3 tools/rom.py words targets/msm8930-r1.2 0x10ce0 24
python3 tools/rom.py strings targets/msm8930-r1.2 --min-length 8
python3 tools/rom.py symbols targets/msm8930-r1.2
```

Every command verifies the artifact's size/hash and all symbol byte anchors
before producing output. Disassembly is **bounded linear ARM inspection**,
not automatic code/data classification or a recovered control-flow graph.
Literal pools and strings can decode as plausible instructions.

Numeric symbol matches are not pointer evidence. For example, the copy
descriptor's length `0x20` happens to equal the reset-entry address. The tool
labels this as a value match, not a branch or pointer.

## Annotation contract

[`symbols.json`](targets/msm8930-r1.2/symbols.json) contains analyst-assigned
names, not recovered vendor symbols:

- **observed**: the stated mechanism is directly supported by instructions
  or data. This means static observation, not hardware execution tracing.
- **inferred**: a semantic role is supported by the mechanism and context,
  but the vendor name/type or some details remain unverified.
- **candidate**: a useful lead whose internal contract is not yet mapped.

Each entry has an address, kind (`function`, `label` or `data`), confidence,
summary, and exact byte anchors. Matching anchors protect against stale
annotations; they do **not** automatically prove the prose interpretation.
Review the instruction windows and caller/callee relationships too.

All addresses are byte addresses. With this base-zero image, ROM addresses
also equal file offsets. RAM/MMIO locations described in the walkthrough
are references made by the ROM, not additional captured memory.

## Evidence

Fetch the notes separately:

```sh
git fetch origin refs/notes/evidence:refs/notes/evidence
git log --oneline
git notes --ref=evidence show <commit>
```

The import and first-pass analysis commits carry self-contained evidence
notes. The manifest also points to the original acquisition note in
[`samcday/pocketboot`](https://github.com/samcday/pocketboot), commit
`4b7685eac406948aed645f2f4377649af3b3b28e`, under the same notes ref.
No large logs or generated full-ROM disassemblies need to be committed.

## Firmware rights

The ROM is third-party Qualcomm firmware. Its original notice is preserved;
see the [target notice](targets/msm8930-r1.2/NOTICE.md). Readability is not a
redistribution license. No project license is applied to the firmware, and
no blanket license has yet been selected for the authored tools/analysis.
