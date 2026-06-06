#!/usr/bin/env python3
"""TFTP server that delivers file data via two IP fragments.

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

Exercises GRUB's IPv4 fragment reassembly (ip.c).

The TFTP handshake (RRQ → OACK → ACK 0) uses normal UDP sockets.
Only the DATA block is sent as fragmented IP using a raw socket with
IP_HDRINCL so that we control the fragment offset and MF fields:

  fragment 1: IP header + UDP header   (8 bytes IP payload, MF=1, offset=0)
  fragment 2: IP header + TFTP DATA  (104 bytes IP payload, MF=0, offset=8)

GRUB must reassemble both fragments before it can parse the UDP header
and deliver the datagram to its TFTP handler.

The file served is always FILE_2FRAG (100 bytes of 0x41 'A') for the
two-fragment scenario, or FILE_3FRAG (150 bytes of 0x42 'B') for the
three-fragment scenario.  The client selects the scenario by requesting
the filename '2frag' or '3frag'.  Any other name defaults to 2frag.

Usage: frag_tftp_server.py <bind-ip>
Exits with status 1 if the bind fails (tap0 not yet up).
"""

import socket
import struct
import sys

TFTP_PORT  = 69
TFTP_RRQ   = 1
TFTP_OACK  = 6
TFTP_ACK   = 4
TFTP_DATA  = 3

FILE_2FRAG = b'A' * 100   # served as 2 IP fragments
FILE_3FRAG = b'B' * 150   # served as 3 IP fragments

FRAG_IP_ID_2 = 0x4742     # arbitrary identification field for 2-frag datagram
FRAG_IP_ID_3 = 0x4743     # arbitrary identification field for 3-frag datagram
FRAG_IP_ID_M = 0x4744     # identification field used for the missing-frag scenario

_IPPROTO_UDP = 17


def _checksum(data: bytes) -> int:
    """Compute the RFC 1071 one's-complement checksum."""
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def _ip_hdr(src: str, dst: str, proto: int, payload_len: int,
            ip_id: int, frag_offset_bytes: int, more: bool) -> bytes:
    """Build a 20-byte IPv4 header with the given fragment fields."""
    flags_off = (frag_offset_bytes >> 3) & 0x1fff
    if more:
        flags_off |= 0x2000  # MF
    hdr = struct.pack('!BBHHHBBH4s4s',
                      0x45, 0,                  # ver/ihl, tos
                      20 + payload_len,          # total length
                      ip_id,                     # identification
                      flags_off,                 # flags + fragment offset
                      64, proto, 0,              # ttl, proto, cksum=0
                      socket.inet_aton(src),
                      socket.inet_aton(dst))
    cksum = _checksum(hdr)
    return hdr[:10] + struct.pack('!H', cksum) + hdr[12:]


def _udp_hdr(src_port: int, dst_port: int, udp_len: int) -> bytes:
    """Build a UDP header with checksum disabled (0)."""
    return struct.pack('!HHHH', src_port, dst_port, udp_len, 0)


def _send_two_fragments(raw_sock, src_ip: str, dst_ip: str,
                        src_port: int, dst_port: int,
                        udp_payload: bytes) -> None:
    """Send a UDP datagram split into two IP fragments.

    The split is placed immediately after the UDP header so that fragment 1
    contains only the 8-byte UDP header (IP payload bytes 0-7) and fragment 2
    contains the full UDP payload (IP payload bytes 8+).  GRUB cannot parse
    the UDP datagram until both fragments are reassembled.
    """
    udp_len = 8 + len(udp_payload)
    udp_hdr = _udp_hdr(src_port, dst_port, udp_len)

    frag1 = _ip_hdr(src_ip, dst_ip, _IPPROTO_UDP, 8,
                    FRAG_IP_ID_2, 0, more=True) + udp_hdr
    frag2 = _ip_hdr(src_ip, dst_ip, _IPPROTO_UDP, len(udp_payload),
                    FRAG_IP_ID_2, 8, more=False) + udp_payload

    raw_sock.sendto(frag1, (dst_ip, 0))
    raw_sock.sendto(frag2, (dst_ip, 0))


def _send_three_fragments(raw_sock, src_ip: str, dst_ip: str,
                          src_port: int, dst_port: int,
                          udp_payload: bytes) -> None:
    """Send a UDP datagram split into three IP fragments.

    IP payload layout:
      bytes  0- 7  UDP header                          → fragment 1 (offset=0)
      bytes  8-15  first 8 bytes of UDP payload        → fragment 2 (offset=8)
      bytes 16-end remaining UDP payload               → fragment 3 (offset=16)

    Fragment 1 arrives, pushed to the priority queue; no asm_netbuff yet.
    Fragment 2 arrives, pushed; still no asm_netbuff (MF=1).
    Fragment 3 arrives (MF=0): asm_netbuff allocated, assembly loop pops all
    three fragments in offset order and copies them in one pass.  This
    exercises the priority queue with multiple elements.
    """
    udp_len = 8 + len(udp_payload)
    ip_payload = _udp_hdr(src_port, dst_port, udp_len) + udp_payload

    # All non-last fragment payloads must be a multiple of 8 bytes.
    frag1 = _ip_hdr(src_ip, dst_ip, _IPPROTO_UDP, 8,
                    FRAG_IP_ID_3, 0, more=True) + ip_payload[0:8]
    frag2 = _ip_hdr(src_ip, dst_ip, _IPPROTO_UDP, 8,
                    FRAG_IP_ID_3, 8, more=True) + ip_payload[8:16]
    frag3 = _ip_hdr(src_ip, dst_ip, _IPPROTO_UDP, len(ip_payload) - 16,
                    FRAG_IP_ID_3, 16, more=False) + ip_payload[16:]

    raw_sock.sendto(frag1, (dst_ip, 0))
    raw_sock.sendto(frag2, (dst_ip, 0))
    raw_sock.sendto(frag3, (dst_ip, 0))


def _parse_rrq_filename(pkt: bytes) -> str:
    """Extract the filename from a TFTP RRQ packet."""
    # RRQ: opcode(2) | filename\0 | mode\0
    parts = pkt[2:].split(b'\x00')
    if not parts or not parts[0]:
        return ''
    try:
        return parts[0].decode('utf-8')
    except UnicodeDecodeError:
        return ''


def main():
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} <bind-ip>', file=sys.stderr)
        sys.exit(1)

    bind_ip = sys.argv[1]

    rrq_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rrq_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        rrq_sock.bind((bind_ip, TFTP_PORT))
    except OSError:
        sys.exit(1)

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                             socket.IPPROTO_RAW)
    raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    while True:
        try:
            pkt, client_addr = rrq_sock.recvfrom(1024)
        except Exception:
            continue

        if len(pkt) < 4:
            continue
        if struct.unpack('!H', pkt[:2])[0] != TFTP_RRQ:
            continue

        client_ip, client_port = client_addr
        filename = _parse_rrq_filename(pkt)
        three_frags  = '3frag'      in filename
        missing_frag = 'missingfrag' in filename
        content = FILE_3FRAG if three_frags else FILE_2FRAG

        # TID socket for the OACK/ACK exchange.
        tid_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tid_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tid_sock.bind((bind_ip, 0))
        tid_sock.settimeout(5.0)
        server_tid = tid_sock.getsockname()[1]

        oack = (struct.pack('!H', TFTP_OACK)
                + b'blksize\x00512\x00'
                + b'tsize\x00' + str(len(content)).encode() + b'\x00')
        tid_sock.sendto(oack, (client_ip, client_port))

        try:
            ack, _ = tid_sock.recvfrom(512)
        except socket.timeout:
            tid_sock.close()
            continue

        if len(ack) < 4:
            tid_sock.close()
            continue
        ack_op, ack_blk = struct.unpack('!HH', ack[:4])
        if ack_op != TFTP_ACK or ack_blk != 0:
            tid_sock.close()
            continue

        if missing_frag:
            # Send only the first fragment (MF=1, offset=0) and return.
            # Fragment 2 is deliberately withheld so GRUB's reassembly buffers
            # frag1 in its priority queue but never allocates asm_netbuff
            # (which only happens when MF=0 arrives).  GRUB's TFTP layer polls
            # until its read timeout fires, then returns an error.  The server
            # closes the TID socket immediately so that each retransmitted RRQ
            # from GRUB is handled as a fresh exchange — this keeps the server
            # non-blocking and ensures it can respond to subsequent RRQs for
            # the 2frag / 3frag filenames if those arrive later.
            udp_len = 8 + len(struct.pack('!HH', TFTP_DATA, 1) + content)
            udp_hdr = _udp_hdr(server_tid, client_port, udp_len)
            frag1_only = (_ip_hdr(bind_ip, client_ip, _IPPROTO_UDP, 8,
                                  FRAG_IP_ID_M, 0, more=True) + udp_hdr)
            raw_sock.sendto(frag1_only, (client_ip, 0))
            tid_sock.close()
            continue

        # Send DATA block 1 as fragmented IP packets.
        tftp_payload = struct.pack('!HH', TFTP_DATA, 1) + content
        if three_frags:
            _send_three_fragments(raw_sock, bind_ip, client_ip,
                                  server_tid, client_port, tftp_payload)
        else:
            _send_two_fragments(raw_sock, bind_ip, client_ip,
                                server_tid, client_port, tftp_payload)

        # Drain ACK 1 to complete the exchange cleanly.
        try:
            tid_sock.recvfrom(512)
        except Exception:
            pass
        finally:
            tid_sock.close()


if __name__ == '__main__':
    main()
