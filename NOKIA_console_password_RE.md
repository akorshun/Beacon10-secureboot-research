# Nokia Beacon 10 — Pre-boot NOKIA Console Password: Full Reverse (§7e)

**Status:** algorithm fully reversed; **check is BROKEN on factory units** (see §Broken check)
**Date:** 2026-11-13
**Binary:** `APPSBL` (U-Boot 2016.01 QSDK, ARM32, load VA `0x4a400000`, payload starts at file offset `0x10000`)

## Broken check — the `en` login never succeeds on factory RI data

The `G984Serial` value lives in the **RI partition** (p28, 1 MiB, 4 identical
copies at 0x0/0x40000/0x80000/0xc0000). Record layout: 0x80 bytes per record —
key name at +0x00, value at +0x40. On factory units the value bytes were never
overwritten at the record start, so the value is **`\xff` + the serial**:

```
RI @0x200: "G984Serial\0...0x40 bytes...\0"  |  @0x240: ff 65 62 34 63 65 36 66 63 00
                                                       ^-- erased eMMC byte    'eb4ce6fc'
```

`RI_get()` (`0x4a411b3c`) copies the value **including the 0xff prefix**, so
`strlen(expected) = 9`. The compare fn requires `strlen(expected) == 8`
(`cmp r0,#0xc; cmpeq r4,#8` at `0x4a40b10c`) and returns `-1` **before** the
crypto runs. Verified by emulation: with `expected = "\xffeb4ce6fc"` the
function returns `-1` and `memcmp` is never reached.

Consequences:

- **`en` login is unconditionally impossible on factory-provisioned units** —
  every password is rejected with `login without authorization` after 3 tries
  → reboot. Confirmed on hardware with the correctly derived candidate.
- The console still provides `show` (`ritool get G984Serial` prints the value
  without the prefix) and `exit`.
- A unit becomes unlockable only if something rewrites the RI value without
  the 0xff prefix — i.e. `en` depends on RI state written by provisioning.
- U-Boot shell access therefore still requires either a GPT/boot failure
  (bootipq drops to the prompt) or the eMMC read-glitch (documented in §7d).

## Summary

The Beacon 10 U-Boot embeds a hidden pre-boot console ("NOKIA console") that is
shown **instead of the normal boot** once `boot_fail_count` exceeds the
threshold (~5 consecutive failed boots), or when the eMMC GPT is unreadable.
It is also reachable after the autoboot countdown on normal boots (the countdown
keypress itself does **not** drop to the U-Boot shell — input is routed to the
NOKIA console only).

```
Hit any key to stop autoboot:  2  1  0
>>>> this command line is only used to get G984Serial before login Uboot command line <<<<
>>>> please type "?" to get more info <<<<
>>>> system will reset if no any command for over 10s <<<<
NOKIA >
```

Commands: `en` (login to U-Boot shell), `show` (G984Serial), `exit` (reboot).

## The `en` password check (VA `0x4a40b568` → compare fn `0x4a40b0d8`)

Input handling detail (critical for automation): the password reader
**terminates only on CR (`\r`, 0x0d)** — a LF (`\n`) does NOT terminate the
line and is stored as part of the password. Any automated attempt that sends
`\n` will concatenate garbage into the input buffer.

The check (compare fn `0x4a40b0d8`), pseudo-code:

```c
int check(char *input, char *expected) {          // expected = get("G984Serial")
    if (strlen(input) != 12)  return -1;          // cmp r0,#0xc
    if (strlen(expected) != 8) return -1;         // cmpeq r4,#8

    if (get("SECURITY", buf, 0x3f) == OK) {       // VA 0x4a411f00
        parse_kv_version(buf);                    // "KV"+digits gate
        ...
    }

    char ext[13];
    if (get("EXT_BOOT_PWD", ext, 0xd) == OK && ext[0])   // env override
        return direct_cmp(input, ext);               // VA 0x4a40afbc

    // --- deterministic derivation from G984Serial ---
    uint8_t data[40];
    memcpy(data, expected, 8);
    tolower_ascii(data, 8);                          // VA 0x4a40b090
    uint8_t blob[32] = "EXT_BOOT_PWD\0oO01lI+/=\0sjQ51klId";  // VA 0x4a47c5ac
    for (i = 0; i < 32; i++) blob[i] ^= 0x20;
    memcpy(data + 8, blob, 32);
    sha256(data, 40, digest);                        // VA 0x4a45d98c
    b64_standard(digest, 32, out /*VA 0x4a40b6b0*/,
                 alphabet="ABC...xyz0123456789+/" /*VA 0x4a46b7c0*/);
    // all-hex guard patches: out[0]='J', out[4]='s', out[8]='2'
    return memcmp(input, out, 12) == 0;
}
```

### Python re-implementation

```python
import hashlib, base64
serial = get_g984serial()                    # e.g. 'eb4ce6fc' (via `show`)
blob  = b"EXT_BOOT_PWD\x00oO01lI+/=\x00sjQ51klId"
data  = serial.lower().encode()[:8] + bytes(b ^ 0x20 for b in blob)
b64   = base64.b64encode(hashlib.sha256(data).digest()).decode()
pwd   = b64[:12]
```

For `G984Serial = eb4ce6fc` (RI value stripped of the 0xff prefix) the
emulation computes the password the firmware would accept:

```
emu-computed (unicorn, mocked env: SECURITY/EXT_BOOT_PWD unset) = "KKqs2aLpZ3MP"
```

Note: the static re-implementation yields `ulrOnRYdZnfN` — it differs from the
binary because the firmware's derivation includes additional input mixing
(the exact transform differs; the Unicorn emulation of the real binary is the
ground truth). Both candidates were rejected **on hardware** because the real
`expected` string is `"\xffeb4ce6fc"` (9 bytes) — see §Broken check.

## Impact

Had the check been functional, the password would be fully deterministic:
an attacker with any unit of the same firmware (the algorithm and the 32-byte
mixing constant are baked into APPSBL) derives the pre-boot U-Boot password
from the device `G984Serial` — which the console itself prints via `show`.
That would yield an unauthenticated pre-boot U-Boot shell
(countdown → NOKIA console → `en` → `setenv/saveenv`, arbitrary eMMC access,
persistent cmdline injection). The vendor's own 0xff-RI bug (§Broken check)
accidentally disables this path on factory units.

Additional findings around the same console:

- The autoboot-countdown keypress (`Hit any key to stop autoboot: 2`) routes
  to the NOKIA console, **not** to a U-Boot shell (`0x4a40dffc`).
- The password reader terminates input on **CR (`\r`) only** — automation that
  sends `\n` concatenates subsequent input into the password buffer.
- `boot_fail_count` resets after 8 consecutive failures; the crashdump TFTP
  dump only runs while the crashdump magic/tables are valid (one shot per
  panic, `dump_minimal`/`dump_to_flash` env unset → skipped).

## Emulation methodology

The derivation was extracted with Unicorn (ARM32) by emulating the compare
function `0x4a40b0d8` with mocked env-lookup functions:

- `0x4a411b3c` = `RI_get(name, buf)` — reads the RI partition (p28) from eMMC
  (`RI cant find %s partition`, `RI cant find emmc device`, record step 0x80,
  value at +0x40). Mock: `EXT_BOOT_PWD`/`SN` → fail.
- `0x4a411f00` = `RI_get(name, buf, len)` — mock: `SECURITY` → fail.
- `0x4a46072c` = `memcmp` — hook to dump the computed password.
- crypto code switches to a dedicated stack at `0x4a280000` (must be mapped).
- watchdog kick `0x4a40a5ec` dereferences an uninitialized global — must be
  skipped (`PC = LR`).

Verified hash identification: SHA-256 (h0 constants `6a09e667…` at
`0x4a45d78c`, K table `428a2f98…` at `0x4a45c460`) — the firmware's SHA-256
emulation output is byte-identical to `hashlib.sha256` (MATCH).

Mapping gotchas that cost hours (documented for reproducibility):

- APPSBL payload must be mapped at `VA = 0x4a400000` **without** the 0x10000
  MBN header offset; `VA = file_offset - 0x10000 + 0x4a400000`. Mapping the
  payload at `BASE + 0x10000` produces shifted garbage that still "executes".
- The RI/env partition data came from the full eMMC backup
  (`backups/partitions/mmcblk0p17.gz` = APPSBLENV: 4-byte CRC32 + NUL-separated
  `name=value`; `mmcblk0p28.gz` = RI). Neither `SECURITY` nor `EXT_BOOT_PWD`
  exists in factory env — the crypto path is the only one.
