#!/usr/bin/env python3
"""Minimal authoritative DNS server for GRUB integration testing.

Copyright (C) 2026  Free Software Foundation, Inc.

GRUB is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

GRUB is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with GRUB.  If not, see <http://www.gnu.org/licenses/>.

Usage: dns_server.py <bind-ip> <hostname>=<ip> [<hostname>=<ip> ...]

Listens on UDP port 53 and responds to A and AAAA queries for registered
hostnames.  The record type is inferred from the IP address format: addresses
containing ':' are treated as IPv6 (AAAA) records; all others are IPv4 (A).
Exits with status 1 if it cannot bind, so that a retry loop in the caller
can wait for the network interface to come up before trying again.

With the DNS_OPTION_PREFER_IPV4 fix in grub_cmd_nslookup, GRUB sends an A
query followed by an AAAA query for each hostname.  The server responds to
whichever type(s) it has records for and returns NXDOMAIN for the rest.
"""
import socket
import struct
import sys

DNS_PORT = 53

# DNS header flags (byte 2 of the 12-byte header, RFC 1035 §4.1.1).
# GRUB stores the two flags bytes as separate uint8 fields:
#   flags      = QR(1) OPCODE(4) AA(1) TC(1) RD(1)
#   ra_z_rcode = RA(1) Z(3) RCODE(4)
_FLAGS_RESPONSE = 0x84   # QR=1, OPCODE=0, AA=1, TC=0, RD=0
_FLAGS_NOERROR  = 0x00   # RA=0, Z=0, RCODE=0 (NOERROR)
_FLAGS_SERVFAIL = 0x02   # RA=0, Z=0, RCODE=2 (SERVFAIL)
_FLAGS_NXDOMAIN = 0x03   # RA=0, Z=0, RCODE=3 (NXDOMAIN)

_QTYPE_A    = 1
_QTYPE_AAAA = 28

_QCLASS_IN  = 1


def _parse_qname(data, offset):
    """Return (dotted_name, offset_after_qname_null) for an uncompressed name."""
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0:
            raise ValueError("unexpected compression pointer in query")
        offset += 1
        labels.append(data[offset:offset + length].decode('ascii'))
        offset += length
    return '.'.join(labels), offset


def _build_a_response(request, question, ipv4_str):
    """Build a DNS A-record response packet."""
    tx_id   = request[0:2]
    header  = tx_id + bytes([_FLAGS_RESPONSE, _FLAGS_NOERROR])
    header += struct.pack('!HHHH', 1, 1, 0, 0)  # QDCOUNT=1, ANCOUNT=1

    # Answer record: name is a pointer back to byte 12 (start of question).
    answer  = b'\xc0\x0c'
    answer += struct.pack('!HH', _QTYPE_A, _QCLASS_IN)
    answer += struct.pack('!I', 60)                  # TTL
    answer += struct.pack('!H', 4)                   # RDLENGTH
    answer += socket.inet_aton(ipv4_str)             # RDATA (4 bytes)

    return header + question + answer


def _build_aaaa_response(request, question, ipv6_str):
    """Build a DNS AAAA-record response packet."""
    tx_id   = request[0:2]
    header  = tx_id + bytes([_FLAGS_RESPONSE, _FLAGS_NOERROR])
    header += struct.pack('!HHHH', 1, 1, 0, 0)  # QDCOUNT=1, ANCOUNT=1

    # Answer record: name is a pointer back to byte 12 (start of question).
    answer  = b'\xc0\x0c'
    answer += struct.pack('!HH', _QTYPE_AAAA, _QCLASS_IN)
    answer += struct.pack('!I', 60)                              # TTL
    answer += struct.pack('!H', 16)                             # RDLENGTH
    answer += socket.inet_pton(socket.AF_INET6, ipv6_str)       # RDATA (16 bytes)

    return header + question + answer


def _build_nxdomain(request, question):
    """Build a DNS NXDOMAIN (RCODE=3) response packet."""
    tx_id   = request[0:2]
    header  = tx_id + bytes([_FLAGS_RESPONSE, _FLAGS_NXDOMAIN])
    header += struct.pack('!HHHH', 1, 0, 0, 0)  # QDCOUNT=1, ANCOUNT=0
    return header + question


def _build_servfail(request, question):
    """Build a DNS SERVFAIL (RCODE=2) response packet."""
    tx_id   = request[0:2]
    header  = tx_id + bytes([_FLAGS_RESPONSE, _FLAGS_SERVFAIL])
    header += struct.pack('!HHHH', 1, 0, 0, 0)  # QDCOUNT=1, ANCOUNT=0
    return header + question


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <bind-ip> [hostname=ip ...]",
              file=sys.stderr)
        sys.exit(1)

    bind_ip = sys.argv[1]

    # Separate A, AAAA, and error-response tables.
    # Use hostname=SERVFAIL to make the server return RCODE=2 for that name.
    a_records      = {}    # hostname -> IPv4 string
    aaaa_records   = {}    # hostname -> IPv6 string
    servfail_hosts = set() # hostnames that always get RCODE=2 (SERVFAIL)
    for arg in sys.argv[2:]:
        host, sep, ip = arg.partition('=')
        if not sep:
            continue
        host = host.lower().rstrip('.')
        if ip == 'SERVFAIL':
            servfail_hosts.add(host)
        elif ':' in ip:
            aaaa_records[host] = ip
        else:
            a_records[host] = ip

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((bind_ip, DNS_PORT))
    except OSError:
        # Signal to the retry loop that the interface is not ready yet.
        sys.exit(1)

    while True:
        try:
            data, addr = sock.recvfrom(512)
        except Exception:
            continue

        # DNS header is 12 bytes; need at least header + 1-byte QNAME + 4
        if len(data) < 17:
            continue

        try:
            qname, after_qname = _parse_qname(data, 12)
        except (ValueError, UnicodeDecodeError):
            continue

        if after_qname + 4 > len(data):
            continue

        qtype, qclass = struct.unpack('!HH', data[after_qname:after_qname + 4])
        question = data[12:after_qname + 4]

        if qclass != _QCLASS_IN:
            continue

        hostname = qname.lower().rstrip('.')

        if hostname in servfail_hosts:
            response = _build_servfail(data, question)
        elif qtype == _QTYPE_A and hostname in a_records:
            response = _build_a_response(data, question, a_records[hostname])
        elif qtype == _QTYPE_AAAA and hostname in aaaa_records:
            response = _build_aaaa_response(data, question, aaaa_records[hostname])
        else:
            response = _build_nxdomain(data, question)

        try:
            sock.sendto(response, addr)
        except OSError:
            pass


if __name__ == '__main__':
    main()
