# Working on Bootromancy

- This is firmware analysis, not a collection of assumed vendor symbols.
  Analyst-assigned names must say what the evidence establishes, not what
  a familiar-looking function ought to do.
- Keep observations, inferred roles, and unresolved candidates distinct.
  Anchor important claims to exact ROM addresses and bytes. A nearby filename
  string is not a function entrypoint; a `bx` is not by itself proof of Thumb.
- The target manifest and symbol map are the sources of truth. Verify the
  artifact hash and annotation anchors before generating disassembly.
  Generated listings belong in `out/`, not in Git.
- Preserve acquired ROMs byte-for-byte, including padding. A repeated read
  establishes repeatability, not silicon immutability or a redistribution
  license. Firmware notices and rights are separate from authored analysis.
- Keep commands, logs, measurements and detailed reasoning in
  `refs/notes/evidence` on the commit they support. Committed documentation
  should present the resulting map and link to that evidence.
- Tools operate offline. Hardware experiments are separate, explicitly
  requested work; do not execute firmware or silently touch a connected phone.
