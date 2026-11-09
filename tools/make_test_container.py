# One-off: build bootipq container variants to probe the pre-auth load flow.
# Base: hlos-openwrt.bin (our OpenWrt FIT container, already parsed correctly
# by bootipq up to the signature check).
import struct
import sys

base = open(r'C:\Users\razor\.zcode\workspace\draft-670271fe-8cde-4c79-a0d0-7faa6e8969ba\beacon10\hlos-openwrt.bin', 'rb').read()
assert len(base) == 10 * 1024 * 1024

# phdr table at 0x34, 3 entries x 32 bytes: ph2 (PT_LOAD) at 0x74
PH2 = 0x74
p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
    struct.unpack('<8I', base[PH2:PH2 + 32])
print('stock phdr2: type=%d off=%#x vaddr=%#x paddr=%#x filesz=%#x' %
      (p_type, p_offset, p_vaddr, p_paddr, p_filesz))

def make(name, vaddr, offset=None, filesz=None, paddr=None):
    b = bytearray(base)
    v = p_vaddr if vaddr is None else vaddr
    o = p_offset if offset is None else offset
    f = p_filesz if filesz is None else filesz
    pa = v if paddr is None else paddr
    struct.pack_into('<8I', b, PH2, p_type, o, v, pa, f, f, p_flags, p_align)
    open(name, 'wb').write(bytes(b))
    print(name, '-> vaddr=%#x offset=%#x filesz=%#x' % (v, o, f))

# control: same as v2 (should behave exactly like the previous clean auth fail)
make('probe_a_ctl.bin', vaddr=0x44000000)
# diagnostic: point the 10 MiB partition read at U-Boot's own load region
make('probe_b_uboot.bin', vaddr=0x4a400000)
# diagnostic: point it at the control FDT / heap area seen in env (fdtcontroladdr 0x4a514004)
make('probe_c_fdt.bin', vaddr=0x4a514000)
