# Pre-auth attack surface — what is actually parsed before the signature verdict (2026-11-14)

Follow-up to the escalation analysis (§5) and an external review suggestion that
FIT parsing / CPU-side parsing happens before authentication and is therefore not
subject to the XPU DMA geometry.

## Verified call order (probe A log, clean auth fail)

```
Parsing phdr load addr 0x0        offset 0x0    size 0x94    type 0x0
Parsing phdr load addr 0x0        offset 0x1000 size 0xe48   type 0x0
Parsing phdr load addr 0x44000000 offset 0x2000 size 0x5bba64 type 0x1
Kernel image authentication failed
BUG: failure at board/qca/arm/common/cmd_bootqca.c:937/do_boot_signedimg()!
BUG!
```

Everything else — `Use partnumber ... named dtb`, `Get fit config name`,
`## Loading kernel from FIT Image`, `Verifying Hash Integrity`, the libfdt config
selection, kernel decompression — happens **after** the verdict (visible in any
successful stock boot log). **The FIT is never parsed before authentication.**
That closes the "pre-auth libfdt / FIT-structure overflow in U-Boot (CPU-side,
unrestricted by XPU geometry)" surface: pre-auth the CPU only

1. scans the 3 program headers (constant bound 3, returns the first PT_LOAD's
   fields — the only attacker-controlled arithmetic is `dest = p_vaddr -
   p_offset`, an integer underflow that just produces a wild DMA destination,
   which XPU denies), and
2. issues the SCM `qca_scm_auth_kernel` call with the image base.

## The remaining pre-auth surface: the QSEE/secapp metadata parser

`phdr1` (type 0, size 0xe48 in stock) is the secboot metadata descriptor. QSEE
(secure world) parses the metadata blob itself from the already-read image
buffer — this is the code that hangs on `p_offset/p_filesz = 0xffffffff` (§7c):
a pre-verdict, attacker-influenced read/walk in the secure world.

Facts from the QSEE image (p5/p6 backup, ELF64 **AArch64**, entry `0x4a600000`,
1.8 MiB, no phdrs = single flat image):

- it is a full TZBSP; the secboot logic is an OEM secapp
  (`/secboot/deferred_oem`, `/secboot/oem_secapp` resource paths),
- metadata format strings embedded: `SSD_METADATA`, `MD_SIGN`, `MD_VERSION`,
  `SW_VERSION`, `IMG_ENC_*`, `MD_SIGNATURE` (XML-like v6/v7 metadata),
- `Invalid auth key received`, `num_segments`, ICE key derivation labels.

Exploitability of the hang is unknown: if the `p_offset`-driven walk is a plain
pointer dereference (wild read → secure data abort → hang), it is a DoS only
(§7c). If any length field from the metadata blob drives a copy into a fixed
secure-world buffer, it is a secure-world overflow → could flip the auth result
→ `bootipq` boots an unsigned kernel → automatic UART-free OpenWrt. Determining
which requires reversing the secapp parser (AArch64, no symbols) — the metadata
format itself is partially documented in CAF secboot sources, which helps.

## Status

| surface | verdict |
|---|---|
| pre-auth FIT/libfdt parse in U-Boot | **does not exist** (post-auth, verified by probe A log order) |
| pre-auth phdr scan in bootipq | validated loop, no exploitable primitive found |
| QSEE/secapp metadata parser | **open** — hang proves pre-verdict parsing; copy-vs-dereference unknown; reversing required |
| SCM verdict glitching | hardware-only (ChipWhisperer-class), not attempted |
| UART automation (Pico) | known working fallback |
