# One-off: probe cycle v2 — correct state machine:
# [prompt] -> bootipq -> stock -> dd p24 -> reboot -> [prompt] -> bootipq -> capture verdict.
import time, warnings
import paramiko
import serial

warnings.filterwarnings('ignore')
BB = r'C:\Users\razor\.zcode\workspace\draft-670271fe-8cde-4c79-a0d0-7faa6e8969ba\beacon10'
KEY = BB + r'\Beacon10-Getshell\nokiakey'
STOCK = dict(hostname='192.168.12.1', username='root', keyfile=KEY)

def stock_ssh(cmd, timeout=180, stdin_file=None):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(STOCK['hostname'], username=STOCK['username'], key_filename=STOCK['keyfile'],
              timeout=15, look_for_keys=False, allow_agent=False)
    i, o, e = c.exec_command(cmd, timeout=timeout)
    if stdin_file:
        i.write(open(stdin_file, 'rb').read())
        i.channel.shutdown_write()
    out = o.read().decode('utf-8', 'replace')
    c.close()
    return out

def wait_stock(timeout=180):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            stock_ssh('echo UP', timeout=15)
            return True
        except Exception:
            time.sleep(15)
    return False

def fresh_prompt():
    """Poke the console and require a fresh prompt echo before typing commands."""
    for _ in range(3):
        ser.reset_input_buffer()
        ser.write(b'\r')
        time.sleep(0.8)
        if b'IPQ9574#' in ser.read(300):
            return True
    return False

ser = serial.Serial('COM21', 115200, timeout=0.3)

def uart_wait_prompt(timeout=180):
    data = bytearray()
    t0 = time.time()
    while time.time() - t0 < timeout:
        chunk = ser.read(4096)
        if chunk:
            data.extend(chunk)
        if b'IPQ9574#' in bytes(data[-160:]):
            return True
        if time.time() - t0 > 12 and not chunk:
            ser.write(b'\r')
            time.sleep(0.8)
    return False

for probe in ('probe_b_uboot.bin', 'probe_c_fdt.bin'):
    print('=' * 22, probe, '=' * 22, flush=True)
    # 1. from the prompt, boot stock
    if not uart_wait_prompt():
        print('[!!] no prompt (hung) — power-cycle needed', flush=True)
        break
    if not fresh_prompt():
        print('[!!] no fresh prompt echo', flush=True)
        break
    ser.write(b'bootipq\r')
    if not wait_stock():
        print('[!!] stock did not come up', flush=True)
        break
    # 2. dd container to p24
    out = stock_ssh('cat > /dev/mmcblk0p24 && sync && md5sum /dev/mmcblk0p24',
                    timeout=180, stdin_file=BB + '\\' + probe)
    print('[dd]', out.strip()[-60:], flush=True)
    # 3. reboot to the prompt
    stock_ssh('reboot')
    if not uart_wait_prompt():
        print('[!!] no prompt after reboot', flush=True)
        break
    # 4. bootipq and capture the outcome
    ser.reset_input_buffer()
    ser.write(b'bootipq\r')
    cap = bytearray()
    t0 = time.time()
    while time.time() - t0 < 75:
        chunk = ser.read(8192)
        if chunk:
            cap.extend(chunk)
    text = bytes(cap).decode('utf-8', 'replace')
    outname = BB + '\\' + probe.replace('.bin', '') + '.bootipq.out'
    open(outname, 'w', encoding='utf-8').write(text)
    if 'Kernel image authentication failed' in text and 'BUG!' in text:
        verdict = 'CLEAN AUTH FAIL'
    elif 'Loading kernel from FIT' in text:
        verdict = 'FIT PARSED — AUTH SKIPPED?!'
    elif 'Starting kernel' in text:
        verdict = 'KERNEL STARTED!'
    else:
        verdict = 'OTHER / DIVERGENCE'
    print('[outcome]', verdict, flush=True)
    print('--- key lines ---', flush=True)
    for key in ('Parsing phdr', 'Kernel image authentication', 'BUG!', 'MMC read', 'Loading kernel', 'Starting kernel', 'Unhandled', 'undefined'):
        k = text.find(key)
        if k >= 0:
            print('  ', text[k:k+110].replace(chr(10), ' '), flush=True)
    print(flush=True)

print('CYCLE DONE')
