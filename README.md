# Nokia Beacon 10: pre-authentication arbitrary write in `bootipq` — and why secure boot still holds

Research on the Qualcomm IPQ9574-based **Nokia Beacon 10** (T-Mobile, FCC 2AD2RBEACOM10),
firmware `2402b.04.09.A17` family (OpenWrt 19.07-SNAPSHOT r123-33e9ef7bb base, vendor build
Sep 2024, U-Boot 2016.01 QSDK, ARM32).

**TL;DR** The vendor `bootipq` boot command parses the attacker-controlled `0:HLOS`
container (a custom ELF32 wrapper holding a FIT image) and loads the **entire partition
(10 MiB) to an attacker-controlled address before the image signature is verified**.
This is a genuine pre-authentication arbitrary-write primitive — but on this product the
Qualcomm XPU places the running bootloader's code and the C stack inside a protected region
that a fixed-size 10 MiB write can never reach without tripping, so the primitive does **not**
escalate to code execution. Secure boot holds. This document describes the full path to the
primitive, the proof-of-concept experiments, and the escalation analysis.

Everything here was performed on devices owned by the author of this repository.
Related: [Beacon10-Getshell](https://github.com/akorshun/Beacon10-Getshell) (root shell on
the stock firmware, used as the entry point), and the
[OpenWrt support PR #26129](https://github.com/openwrt/openwrt/pull/26129) where parts of
this were first discussed.

---

## 1. Entry point: root shell on the stock firmware

The stock web UI is vulnerable to a race-condition command injection
(`troubleshooting_web_app.cgi?ping` racing `usb_web_app.cgi?import` — suspected
CVE-2025-9974), which yields a root shell without UART. Tooling and details:
[Beacon10-Getshell](https://github.com/akorshun/Beacon10-Getshell). From that shell the
eMMC is fully writable (`dd`), which is how every experiment below was delivered.

## 2. The secure boot chain

```
PBL (fuse-root-of-trust) -> SBL1 -> QSEE/TME-L -> APPSBL (U-Boot 2016.01) -> HLOS
```

* SBL1 authenticates every stage it loads (`Auth Metadata` + `Segments hash check` lines in
  the boot log, including `APPSBL`) — **replacing or patching U-Boot on flash is not possible**.
* SBL1 reports `S - Secure Boot: On`; the live U-Boot command
  `is_sec_boot_enabled` answers **"secure boot fuse is enabled"**.
* The vendor `bootipq` command loads `0:HLOS` and extends authentication to the kernel
  through `do_boot_signedimg()` (`cmd_bootqca.c:937`), which delegates to QSEE. An unsigned
  image is rejected with `Kernel image authentication failed` followed by a `BUG!` reset.
* Manual `bootm <addr>#<config>` **bypasses that check** (it never calls
  `do_boot_signedimg`) — which is why the OpenWrt install procedure boots OpenWrt over
  UART with `tftpboot` + `bootm` on every power cycle.
* The vendor autoboot **ignores `bootcmd`** entirely (it runs the `bootipq` slot logic
  directly), so environment-based boot changes do not survive without UART.

## 3. The `0:HLOS` container format (reverse-engineered)

`0:HLOS` (p24, 10 MiB) is a fake-ELF32 container — a real ELF32 header
(`e_phoff=0x34`, 3 program headers, `e_phentsize=0x20`) wrapping a FIT image:

| phdr | type | file offset | vaddr | filesz | content |
|---|---|---|---|---|---|
| 0 | PT_NULL | 0x0 | 0x0 | 0xb4 | header/placeholder |
| 1 | PT_NULL | 0x1000 | 0x0 | 0xe48 | metadata blob (unused by bootipq) |
| 2 | PT_LOAD | 0x2000 | 0x44000000 | 0x391ea4 | **the FIT image** |

`bootipq` flow (verified by console capture and static analysis of the ARM32 payload,
which is loaded at VA 0x4a400000 from file offset 0x10000):

1. Reads the first 148 eMMC blocks (0x12800 bytes) into a heap buffer.
2. A locator function (VA `0x4a4039c4`) validates only the ELF magic and `e_type == 2`,
   then scans **exactly 3 program headers** (a constant `+0x60` bound) and returns the
   **first `PT_LOAD`'s `{p_offset, p_paddr, p_filesz}` with zero validation** of any field.
3. The caller issues `mmc read <dest> <part-start> 20480` — **the entire 10 MiB partition** —
   where `<dest>` is derived from the attacker-controlled `p_vaddr`/`p_offset`.
4. **Only then** `do_boot_signedimg()` authenticates the loaded image (QSEE SCM call).
5. On success the FIT at `loadaddr` is parsed (the FIT config name is derived from the
   device partnumber: `config@3TN00201AB`) and booted.

### The vulnerability

Step 3 writes **10 MiB of fully attacker-controlled bytes (the whole partition content) to
an attacker-chosen address, before any signature check**. Neither `p_vaddr` nor `p_offset`
nor `p_filesz` is validated against the partition size or a load-address whitelist.

## 4. Proof of concept

Three containers differing only in `phdr2.p_vaddr` (all other bytes identical), flashed to
`0:HLOS` from the stock root shell, then `bootipq`:

| probe | `p_vaddr` | window | result |
|---|---|---|---|
| A (control) | 0x44000000 | [0x44000000, 0x4e000000) | clean `Kernel image authentication failed` + `BUG!` + reset (the normal path) |
| B | **0x4a400000** | [0x49ffe000, 0x59ffe000) | **hard reset mid `MMC read` with no authentication message** — the write crossed the live U-Boot/protected region and the board died before the signature check could run |
| D1 | 0x49a42000 | [0x49a40000, 0x4a400000) | read **completes** — proves the region below 0x4a400000 is DMA-writable |

Raw console captures: [`logs/probe_a.bootipq.out`](logs/probe_a_ctl.bin.bootipq.out),
[`logs/probe_b.bootipq.out`](logs/probe_b.bootipq.out), [`logs/probe_d1.out`](logs/probe_d1.out).
Probe builder: [`tools/make_test_container.py`](tools/make_test_container.py).

## 5. Escalation analysis — why this does not break secure boot

To turn the write into code execution one would target either the running bootloader's
**code** or its **C stack** (return-address overwrite):

* U-Boot code+data lives at VA/PA `0x4a400000`–`0x4a4e6f4`
  (`relocaddr = 0x4a400000`, `reloc off = 0`, MMU identity-mapped for DRAM — verified by
  dumping the ARM32 page tables at `TLB addr 0x4a510000`).
* The C stack lives at `0x4a27fxxx` (`sp start = 0x4a27fa80`), i.e. only **~1.6 MiB below**
  the start of the code region.

The blast window is fixed at exactly 10 MiB. Geometry:

* To cover the code region the window must start at `p_vaddr - p_offset ≤ 0x4a400000` and
  therefore always extends ≥ 10 MiB upward, crossing **0x4a400000 itself** — the first byte
  of the XPU-protected bootloader region.
* To cover the stack the window must start at `≥ 0x4a27fa90 - 10 MiB = 0x4027fa90`; any such
  window ends at `≥ 0x4a27fa90`, and every window ending at or beyond `0x4a27fa90` that is
  wide enough to reach downward past the code... cannot: a 10 MiB window covering the stack
  necessarily extends ~8.4 MiB past the stack top, across the 0x4a400000 boundary.
* Empirically: probe B (window crossing 0x4a400000) hard-resets mid-read — the XPU denies
  the DMA write to the bootloader region — while probe D1 (window ending exactly at
  0x4a400000) completes. The boundary sits precisely between the writable world and
  everything worth overwriting.

With the code and stack both unreachable, the remaining writable regions
(free DRAM below `0x4a100000`, and the `0x4a100000`–`0x4a400000` scratch area) contain
nothing that redirects execution. An attempted full exploit
([`tools/build_exploit.py`](tools/build_exploit.py) — memory-image container with the
U-Boot code re-written byte-exact, `do_boot_signedimg` patched to `mov r0,#0; bx lr`,
a shellcode calling `do_bootm` on an embedded OpenWrt FIT, and a stack spray) is included
for documentation; it is **not** expected to work and was never run past the geometry
analysis, for the reasons above.

## 6. Impact and recommendations

* **What an attacker gets**: a pre-authentication (in the secure-boot sense) 10 MiB DMA
  write to an arbitrary address below `0x4a400000`, plus the ability to make `bootipq`
  parse arbitrary FIT structures from memory (the FIT parse itself also processes
  attacker data before any trust decision). On this product neither leads to code
  execution because of the XPU placement.
* **What it means for the design**: the vendor's secure boot survives this attack class —
  but only thanks to XPU region placement, not because the parser is safe. On a SoC or
  board revision where the bootloader is loaded elsewhere (or the XPU is configured
  differently), the same primitive would be lethal.
* **Recommendations to the vendor**:
  1. Validate `p_offset`, `p_vaddr`, `p_filesz` in the ELF/PT_LOAD locator against the
     partition bounds and a load-address whitelist.
  2. Read only `p_filesz` bytes from `p_offset`, not the whole partition.
  3. Keep the XPU protection of the loaded bootloader region (it is the only thing that
     contained this bug).

## 7. Artifacts

```
tools/make_test_container.py   probe container builder
tools/probe_via_uboot.py       probe driver (TFTP + mmc write + bootipq)
tools/probe_cycle2.py          probe driver (stock dd + bootipq state machine)
tools/build_exploit.py         attempted escalation (documented, not viable)
logs/probe_a_ctl.bin.bootipq.out   control probe console capture
logs/probe_b.bootipq.out           crossing-probe console capture (the proof)
logs/probe_d1.out                  boundary probe console capture
```

## 8. Disclosure

Findings were developed 2026-11-06…09 on personal devices and shared publicly in the
[OpenWrt PR #26129](https://github.com/openwrt/openwrt/pull/26129) review thread
([comment 1](https://github.com/openwrt/openwrt/pull/26129#issuecomment-6695091644),
[comment 2](https://github.com/openwrt/openwrt/pull/26129#issuecomment-6727123358)).
Formal notification to Nokia/T-Mobile PSIRT is recommended; no vendor response is required
for this document given the positive security outcome (the XPU contains the primitive).

## 9. Reproduction notes

* UART: 3.3 V, 115200 8N1, pads RXD/TXD/GND (GND = square pad).
* Containers are flashed to `0:HLOS` from the stock root shell: `cat > /dev/mmcblk0p24`.
* After each probe the board returns to the U-Boot prompt (`console=1`,
  `bootretry=-1`, `bootdelay=-1` in `0:APPSBLENV`); restore the factory environment
  (`dd` of the backed-up p17) to return to silent stock autoboot.
* Vendor U-Boot quirks that will bite you: `tftpput` caches its arguments from the first
  call of a session; `fw_setenv` silently drops negative values (`-1` parsed as a flag);
  the eMMC/eth init is flaky on cold boots.
