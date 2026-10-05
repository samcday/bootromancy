# msm8930-r1.2 reconstruction

Byte-exact ARM reconstructions of ROM functions, per the bootromancy standard
(every byte of the compiled artifact is compared against the pinned `pbl.bin`;
nothing is executed by the gate).

## bn_from_bytes — ROM 0x4554..0x45FF (172 bytes)

`bn_from_bytes.s` reconstructs the bignum loader that turns a caller-supplied
blob pointer plus **byte length** into a bignum object in the verifier's
context arena. Its byte length comes straight from parsed per-certificate
state (not from any validated constant), and this loader is the primitive
through which that length reaches the RSA verification path.

This function matters to the signature verification chain because:

1. The signature byte count flows into `bn_from_bytes` from the parsed image,
   and **no code between the parser and RSA re-binds that count to the
   RSA modulus size**. `0xbdf8..0xbffc` applies only a fixed
   2048..4096-bit window (`sig_len * 8` in bounds); the digest compare at
   `0xbf4c` is sized by hash algorithm (0x14 or 0x20), never by modulus size.
2. Everything down this path therefore trusts an attacker-chosen length to
   describe how many bytes of signature to ingest and exponentiate.

Assembling and comparing (`check.py`) proves the compiled artifacts are the
same 172 bytes as the ROM slice:

```
$ make reconstruction
PASS ROM identity: 131072 bytes, sha256 c1a7d8ffc9a3b9581953107861e61d9d7d9b9b2c5dafd929571446614884f92e
PASS asm: 172 exact bytes at 0x00004554, sha256 90b3888a248cc5acfbb4a2c9b8a9218cb18ceb70f4fc5cf7dc315f671fe4696e
PASS rejected compiled mutation: asm-wrong-alloc-return (...)
PASS rejected compiled mutation: asm-inverted-overflow-branch (...)
PASS rejected compiled mutation: asm-swapped-acc-shift (...)
PASS rejected changed ROM byte
PASS rejected truncated ROM
ALL GATES PASSED
```

Three link-time branches target absolute ROM addresses outside the
reconstructable span (alloc `0x4ab8`, byte accessor `0x24dc`, and the
zero-length allocation path branch back to alloc). gas's armv4t backend
resolves absolute-symbol branches with veneers, so those call sites are
committed as `.word` directives in `bn_from_bytes.s`, annotated with the
\@ ROM address each encodes. Every byte inside the function body itself is
breathed out of gas normally (push/pop, arithmetic, conditional forms and
all); only the two absolute calls and the overflow/zero-length branch words
are fixed constants.

### Acceptance gates

| gate | what it establishes |
| --- | --- |
| ROM identity (sha256) | the `pbl.bin` under test is the pinned artifact |
| 172-byte equality | `bn_from_bytes.s` is the same machine code as ROM `[0x4554..0x4600)` |
| Three compiled mutants rejected | the gate cannot be fooled by targeted behavior edits |
| ROM integrity mutants rejected | corrupt/truncated artifacts do not compare |

## Roadmap (not in this PR)

- `0xbdf8..0xbffc` — the signature-length window in the per-certificate
  verify: reconstruct the `sig_len * 8` in-bounds branch byte-exactly.
- `0x4c18..0x4c60` — the modexp entry checks (odd-exponent requirement).
- `0xbf2c..0xbf98` — the digest-compare sizing by hash type.
- `0x4554`-level replay: run both the pinned ROM and these reconstructions
  through the same emulator, asserting identical accept/reject results, to
  tie the byte gate to behavioural equivalence of the verify path.
