# One-off: drive the bootipq probe matrix entirely from the U-Boot prompt
# (COM21): tftpboot the probe container into RAM, mmc write it to 0:HLOS
# (p24: sector 0xc222, 0x5000 blocks), then bootipq and capture the outcome.
import time
import serial

P24_SECTOR = 0xC222
P24_BLOCKS = 0x5000

ser = serial.Serial('COM21', 115200, timeout=0.2)
ser.reset_input_buffer()
buf = bytearray()

def read_for(sec):
    t0 = time.time()
    while time.time() - t0 < sec:
        chunk = ser.read(8192)
        if chunk:
            buf.extend(chunk)

def wait_prompt(timeout=120):
    t0 = time.time()
    while time.time() - t0 < timeout:
        chunk = ser.read(8192)
        if chunk:
            buf.extend(chunk)
        if b'IPQ9574#' in bytes(buf[-160:]):
            return True
        if time.time() - t0 > 10 and not chunk:
            ser.write(b'\r')
            time.sleep(0.8)
    return False

def send(line, wait=2):
    print('>>>', line, flush=True)
    ser.write((line + '\r').encode())
    time.sleep(wait)

def at_prompt_now():
    ser.write(b'\r')
    time.sleep(0.8)
    echo = ser.read(300)
    buf.extend(echo)
    return b'IPQ9574#' in echo

for probe in ('probe_a_ctl', 'probe_b_uboot', 'probe_c_fdt'):
    print('=' * 22, probe, '=' * 22, flush=True)
    if not wait_prompt():
        print('[!!] no prompt before probe - board hung? power-cycle needed', flush=True)
        break
    time.sleep(0.5)
    buf.clear()
    send('tftpboot 0x50000000 %s.bin' % probe, wait=25)
    tftp_ok = b'bytes transferred' in bytes(buf) or b'blocks read' in bytes(buf) or b'######' in bytes(buf)
    print('[tftp]', tftp_ok, flush=True)
    if not tftp_ok:
        print(text := bytes(buf).decode('utf-8', 'replace')[-400:], flush=True)
        continue
    send('mmc write 0x50000000 %#x %#x' % (P24_SECTOR, P24_BLOCKS), wait=25)
    send('bootipq', wait=45)
    cap = read_for(75)
    open(probe + '.uboot.out', 'wb').write(bytes(cap))
    text = bytes(cap).decode('utf-8', 'replace')
    if 'Kernel image authentication failed' in text and 'BUG!' in text:
        verdict = 'CLEAN AUTH FAIL (no deviation)'
    elif 'Loading kernel from FIT' in text:
        verdict = 'FIT PARSED (auth skipped?!)'
    elif 'Starting kernel' in text:
        verdict = 'KERNEL STARTED'
    else:
        verdict = 'OTHER (see %s.uboot.out)' % probe
    print('[outcome]', verdict, flush=True)
    print('--- tail ---')
    print(text[-500:], flush=True)
    # return to prompt for the next probe
    if not at_prompt_now():
        time.sleep(2)
        if not at_prompt_now():
            print('[recover] board not at prompt; sending reset', flush=True)
            ser.write(b'reset\r')
    time.sleep(4)

print('PROBES DONE', flush=True)
