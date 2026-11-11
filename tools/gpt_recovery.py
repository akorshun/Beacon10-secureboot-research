# U-Boot recovery: restore GPT via mw commands + fix fsbootargs
# Catches NOKIA console or U-Boot prompt, injects 705 commands automatically
import serial, time, sys, os, json

COM = 'COM21'
LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gpt_recovery.log')
CMDS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'recovery_data.json')

with open(CMDS_FILE) as f:
    ALL_CMDS = json.load(f)['commands']

PASSWORDS = ['nSW6wc2[uofm', '7lo:p9UzcjrS', '41434c4c', 'ALCLEB4CE6FC', 'ALCL']

log = open(LOG, 'ab')
buf = bytearray()
printed_pos = 0

def rt(msg):
    sys.stdout.write(msg + '\n')
    sys.stdout.flush()
    log.write((msg + '\n').encode())
    log.flush()

def read_and_print(s):
    global printed_pos
    n = s.in_waiting
    if n:
        d = s.read(n)
        buf.extend(d)
        log.write(d)
        log.flush()
    data = bytes(buf)
    start = printed_pos
    while True:
        nl = data.find(b'\n', start)
        if nl < 0: break
        line = data[start:nl]
        clean = line.replace(b'\r', b'').replace(b'\x00', b'')
        try: txt = clean.decode('utf-8', errors='replace').strip()
        except: txt = clean.decode('latin1', errors='replace').strip()
        if txt and len(txt) > 2:
            sys.stdout.write('  ' + txt + '\n')
            sys.stdout.flush()
        start = nl + 1
    printed_pos = start
    if printed_pos > 200000:
        del buf[:printed_pos]
        printed_pos = 0
    return data

def send(s, cmd):
    rt(f'[>] {cmd}')
    s.write((cmd + '\n').encode())
    time.sleep(0.05)  # 50ms between commands to avoid UART overflow

def main():
    s = serial.Serial(COM, 115200, timeout=0.1)
    rt(f'=== GPT Recovery: {len(ALL_CMDS)} commands ===')
    rt(f'=== Power-cycle router now ===')
    rt(f'=== Script catches prompt automatically ===')

    stage = 'wait'
    pw_idx = 0
    cmd_idx = 0
    t0 = time.time()
    buf.clear()
    printed_pos = 0

    while True:
        data = read_and_print(s)
        tail = data[-200:] if len(data) > 200 else data

        if b'NOKIA >' in tail and stage == 'wait':
            rt('[>>] NOKIA console!')
            send(s, 'en')
            stage = 'nokia_pw'
            time.sleep(0.5)
            continue

        if b'Please input password' in tail and stage == 'nokia_pw':
            if pw_idx < len(PASSWORDS):
                rt(f'[>>] pw: {PASSWORDS[pw_idx]}')
                send(s, PASSWORDS[pw_idx])
                pw_idx += 1
                time.sleep(0.5)
                continue
            else:
                rt('[!] passwords exhausted')
                stage = 'wait'; pw_idx = 0

        if b'IPQ9574#' in tail and stage in ('nokia_check', 'wait', 'inject'):
            if stage in ('nokia_check', 'wait') and cmd_idx == 0:
                rt(f'[>>] U-BOOT PROMPT! Injecting {len(ALL_CMDS)} commands...')
                stage = 'inject'
            if cmd_idx < len(ALL_CMDS):
                cmd = ALL_CMDS[cmd_idx]
                send(s, cmd)
                cmd_idx += 1
                # longer wait for critical commands
                if 'mmc write' in cmd:
                    time.sleep(2)
                elif 'saveenv' in cmd:
                    time.sleep(2)
                elif 'reset' in cmd:
                    time.sleep(1)
                    rt('[>>] Reset sent. Waiting for reboot...')
                    stage = 'boot_wait'
                elif cmd_idx % 50 == 0:
                    time.sleep(0.3)
                continue
            else:
                rt('[+] All commands sent!')
                stage = 'done'

        if b'boot finsh' in data[-500:] or b'Linux version' in data[-500:]:
            rt('\n[+] STOCK BOOTED! RECOVERY SUCCESSFUL!\n')
            break

        if time.time() - t0 > 600:  # 10 min total
            rt('[!] 10 min timeout, restarting cycle...')
            stage = 'wait'; pw_idx = 0; cmd_idx = 0
            t0 = time.time()
            buf.clear(); printed_pos = 0

        time.sleep(0.2)

    s.close()
    rt('Script done.')

if __name__ == '__main__':
    main()
