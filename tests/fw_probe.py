"""Run inside a throwaway network namespace: what can this uid reach?

Prints one line per probe. Listeners stand in for the Ghost Tor: a TCP one on
the TransPort that reports where each connection was really going, and a UDP
one on the DNSPort.
"""
import socket, struct, threading, time

out = {}

def trans():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 9140)); s.listen(); s.settimeout(6)
    try:
        while True:
            c, _ = s.accept()
            port, ip = struct.unpack("!2xH4s8x", c.getsockopt(socket.SOL_IP, 80, 16))
            out.setdefault("trans", []).append(f"{socket.inet_ntoa(ip)}:{port}")
            c.close()
    except OSError:
        pass

def dns():
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("127.0.0.1", 9153)); u.settimeout(6)
    try:
        while True:
            data, addr = u.recvfrom(512)
            out.setdefault("dns", []).append(len(data))
            u.sendto(b"ok", addr)
    except OSError:
        pass

def other():                          # a local service that is not Tor
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 631)); s.listen(); s.settimeout(6)
    try:
        while True:
            c, _ = s.accept(); c.close()
    except OSError:
        pass

for f in (trans, dns, other):
    threading.Thread(target=f, daemon=True).start()
time.sleep(0.3)

def tcp(host, port):
    try:
        socket.create_connection((host, port), timeout=1.5).close(); return "connected"
    except OSError as e:
        return type(e).__name__

def udp(host, port):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(1.5)
    try:
        u.sendto(b"\x12\x34" + b"\x00" * 10, (host, port)); u.recvfrom(64); return "answered"
    except OSError as e:
        return type(e).__name__

print("tcp 93.184.216.34:443 ->", tcp("93.184.216.34", 443))
print("udp dns 9.9.9.9:53    ->", udp("9.9.9.9", 53))
print("udp 9.9.9.9:443       ->", udp("9.9.9.9", 443))
print("tcp 127.0.0.1:631     ->", tcp("127.0.0.1", 631))
try:
    s6 = socket.socket(socket.AF_INET6); s6.settimeout(1.5); s6.connect(("::1", 631)); print("tcp6 ::1:631          -> connected")
except OSError as e:
    print("tcp6 ::1:631          ->", type(e).__name__)
time.sleep(0.3)
print("tor saw:", out.get("trans", []), "dns queries:", len(out.get("dns", [])))
