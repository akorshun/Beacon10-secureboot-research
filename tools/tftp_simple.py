import socket, struct, os
RRQ = bytes([0,1])
ACK = bytes([0,4])
HDR = bytes([0,3])
data = open("tftp_root/gpt_restore.bin","rb").read()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0.0.0.0", 69))
print("TFTP READY", len(data), flush=True)
while True:
    try:
        req, addr = sock.recvfrom(600)
        if req[:2] == RRQ:
            print("RRQ", addr, flush=True)
            blk = 1
            for off in range(0, len(data), 512):
                pkt = HDR + blk.to_bytes(2,"big") + data[off:off+512]
                sock.sendto(pkt, addr)
                sock.settimeout(5)
                sock.recvfrom(4)
                blk += 1
            print("DONE", blk-1, flush=True)
    except Exception as e:
        print("err:", e, flush=True)
