#!/usr/bin/env python3

"""Generate a small pcap containing two near-identical HTTP file downloads."""

import argparse
import pathlib
import struct


CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")
CLIENT_IP = "10.9.0.1"
SERVER_IP = "10.9.0.2"
SERVER_PORT = 80
TCP_PAYLOAD_CHUNK = 1200


def ip_bytes(addr):
    return bytes(int(part) for part in addr.split("."))


def checksum(data):
    if len(data) % 2:
        data += b"\x00"

    total = 0
    for offset in range(0, len(data), 2):
        total += (data[offset] << 8) | data[offset + 1]
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def splitmix64(state):
    state = (state + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    z = state
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    z ^= z >> 31
    return state, z & 0xFFFFFFFFFFFFFFFF


def make_body():
    data = bytearray()
    state = 0x434F4E54454E5453

    while len(data) < 16 * 1024:
        state, value = splitmix64(state)
        data.extend(struct.pack("<Q", value))

    return bytes(data[: 16 * 1024])


def make_http_response(name, body):
    header = (
        "HTTP/1.1 200 OK\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Content-Type: application/octet-stream\r\n"
        f"Content-Disposition: attachment; filename={name}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")
    return header + body


def tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload=b"", ident=0):
    src = ip_bytes(src_ip)
    dst = ip_bytes(dst_ip)

    tcp_header = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, 5 << 4, flags, 65535, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp_header) + len(payload))
    tcp_sum = checksum(pseudo + tcp_header + payload)
    tcp_header = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, 5 << 4, flags, 65535, tcp_sum, 0)

    ip_total_len = 20 + len(tcp_header) + len(payload)
    ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_total_len, ident, 0x4000, 64, 6, 0, src, dst)
    ip_sum = checksum(ip_header)
    ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_total_len, ident, 0x4000, 64, 6, ip_sum, src, dst)

    eth = SERVER_MAC + CLIENT_MAC + struct.pack("!H", 0x0800)
    if src_ip == SERVER_IP:
        eth = CLIENT_MAC + SERVER_MAC + struct.pack("!H", 0x0800)

    return eth + ip_header + tcp_header + payload


class PcapWriter:
    def __init__(self, path):
        self.path = path
        self.file = path.open("wb")
        self.file.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        self.ts_usec = 0

    def write(self, packet):
        self.file.write(struct.pack("<IIII", 1_700_000_000, self.ts_usec, len(packet), len(packet)))
        self.file.write(packet)
        self.ts_usec += 1000

    def close(self):
        self.file.close()


def add_http_download(writer, client_port, name, body, base_ident, client_seq, server_seq):
    request = f"GET /{name} HTTP/1.1\r\nHost: files.example\r\nUser-Agent: ssdf-fixture\r\n\r\n".encode("ascii")
    response = make_http_response(name, body)
    ident = base_ident

    def emit(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload=b""):
        nonlocal ident
        ident += 1
        writer.write(tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload, ident))

    emit(CLIENT_IP, SERVER_IP, client_port, SERVER_PORT, client_seq, 0, 0x02)
    emit(SERVER_IP, CLIENT_IP, SERVER_PORT, client_port, server_seq, client_seq + 1, 0x12)
    emit(CLIENT_IP, SERVER_IP, client_port, SERVER_PORT, client_seq + 1, server_seq + 1, 0x10)
    emit(CLIENT_IP, SERVER_IP, client_port, SERVER_PORT, client_seq + 1, server_seq + 1, 0x18, request)

    client_next = client_seq + 1 + len(request)
    server_next = server_seq + 1
    emit(SERVER_IP, CLIENT_IP, SERVER_PORT, client_port, server_next, client_next, 0x10)
    for offset in range(0, len(response), TCP_PAYLOAD_CHUNK):
        chunk = response[offset : offset + TCP_PAYLOAD_CHUNK]
        emit(SERVER_IP, CLIENT_IP, SERVER_PORT, client_port, server_next, client_next, 0x18, chunk)
        server_next += len(chunk)

    emit(CLIENT_IP, SERVER_IP, client_port, SERVER_PORT, client_next, server_next, 0x10)
    emit(SERVER_IP, CLIENT_IP, SERVER_PORT, client_port, server_next, client_next, 0x11)
    emit(CLIENT_IP, SERVER_IP, client_port, SERVER_PORT, client_next, server_next + 1, 0x11)
    emit(SERVER_IP, CLIENT_IP, SERVER_PORT, client_port, server_next + 1, client_next + 1, 0x10)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", nargs="?", type=pathlib.Path, default=pathlib.Path(__file__).with_name("near-identical-http-files.pcap"))
    args = parser.parse_args()

    base = make_body()
    inserted = b"ssdf inserted block: small stable mutation\n" * 2
    near = base[:8192] + inserted + base[8192:]

    writer = PcapWriter(args.output)
    try:
        add_http_download(writer, 51000, "alpha.bin", base, 1000, 100000, 900000)
        add_http_download(writer, 51001, "alpha-near.bin", near, 2000, 200000, 800000)
    finally:
        writer.close()

    print(args.output)


if __name__ == "__main__":
    main()
