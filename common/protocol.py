"""
Protocole de communication client <-> serveur
"""
import json
import struct


def send_packet(sock, data: dict):
    """Envoie un paquet JSON préfixé par sa taille (4 bytes)."""
    raw = json.dumps(data).encode()
    sock.sendall(struct.pack(">I", len(raw)) + raw)


def recv_packet(sock) -> dict:
    """Reçoit un paquet JSON."""
    raw_len = _recv_exact(sock, 4)
    if not raw_len:
        return None
    length = struct.unpack(">I", raw_len)[0]
    if length > 10 * 1024 * 1024:  # max 10MB
        raise ValueError("Paquet trop grand")
    raw = _recv_exact(sock, length)
    if not raw:
        return None
    return json.loads(raw.decode())


def _recv_exact(sock, n: int) -> bytes:
    """Reçoit exactement n bytes."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data
