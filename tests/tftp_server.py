#!/usr/bin/env python3
"""Minimal read-only TFTP server (RFC 1350 + options RFC 2347/2348/2349).

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

Usage: tftp_server.py <root-dir> [<bind-ip>]

Exits with status 1 immediately if it cannot bind to UDP port 69, so that
a retry loop in the caller can wait for the network interface to come up
before trying again.

Each RRQ is handled in its own thread that opens a fresh ephemeral UDP
socket, mirroring the standard TFTP Transfer Identifier (TID) behaviour.
GRUB's UDP layer latches onto the source port of the first packet it
receives (the OACK), so all subsequent ACKs from GRUB are delivered to
that ephemeral port automatically.
"""
import os
import sys
import socket
import struct
import threading

TFTP_RRQ   = 1
TFTP_DATA  = 3
TFTP_ACK   = 4
TFTP_ERROR = 5
TFTP_OACK  = 6

DEF_BLKSIZE = 512
TIMEOUT     = 3.0   # seconds to wait for a single ACK before retransmit
MAX_RETRIES = 5


def _serve_transfer(client_addr, filename, blksize, want_tsize, root):
    """Handle one TFTP RRQ transfer; runs in its own daemon thread."""
    real_root = os.path.realpath(root)
    safe_path = os.path.realpath(os.path.join(real_root, filename.lstrip('/')))
    # Reject path traversal attempts.
    if not (safe_path == real_root or safe_path.startswith(real_root + os.sep)):
        return

    try:
        with open(safe_path, 'rb') as fh:
            data = fh.read()
    except OSError:
        return

    # Open an ephemeral socket for this transfer.  Its source port becomes
    # the server TID that GRUB will direct subsequent ACKs to.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.bind(('', 0))

        # GRUB always sends blksize and tsize options, so we must respond
        # with an OACK and wait for the client's ACK block 0 before sending
        # any DATA packets.
        oack = struct.pack('!H', TFTP_OACK)
        oack += b'blksize\x00' + str(blksize).encode() + b'\x00'
        if want_tsize:
            oack += b'tsize\x00' + str(len(data)).encode() + b'\x00'

        acked = False
        for _ in range(MAX_RETRIES):
            sock.sendto(oack, client_addr)
            try:
                pkt, _ = sock.recvfrom(512)
                if len(pkt) >= 4:
                    op, blk = struct.unpack('!HH', pkt[:4])
                    if op == TFTP_ACK and blk == 0:
                        acked = True
                        break
            except socket.timeout:
                pass

        if not acked:
            return

        block  = 1
        offset = 0
        while True:
            chunk = data[offset:offset + blksize]
            pkt   = struct.pack('!HH', TFTP_DATA, block & 0xFFFF) + chunk
            for _ in range(MAX_RETRIES):
                sock.sendto(pkt, client_addr)
                try:
                    ack, _ = sock.recvfrom(512)
                    if len(ack) >= 4:
                        aop, ablk = struct.unpack('!HH', ack[:4])
                        if aop == TFTP_ACK and ablk == (block & 0xFFFF):
                            break
                except socket.timeout:
                    pass
            # A DATA packet shorter than blksize signals EOF.
            if len(chunk) < blksize:
                break
            block  += 1
            offset += blksize
    finally:
        sock.close()


def main():
    root     = sys.argv[1] if len(sys.argv) > 1 else '.'
    bind_ip  = sys.argv[2] if len(sys.argv) > 2 else ''

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind((bind_ip, 69))
    except OSError:
        # Signal to the retry loop that the interface is not ready yet.
        sys.exit(1)

    while True:
        try:
            pkt, addr = server_sock.recvfrom(1024)
        except Exception:
            continue
        if len(pkt) < 4:
            continue
        op = struct.unpack('!H', pkt[:2])[0]
        if op != TFTP_RRQ:
            continue

        # RRQ layout: opcode(2) | filename\0 | mode\0 | [opt\0 val\0 ...]
        parts = pkt[2:].split(b'\x00')
        if len(parts) < 2 or not parts[0]:
            continue
        try:
            filename = parts[0].decode('utf-8')
        except UnicodeDecodeError:
            continue

        blksize    = DEF_BLKSIZE
        want_tsize = False
        i = 2
        while i + 1 < len(parts) and parts[i]:
            key = parts[i].lower()
            val = parts[i + 1]
            if key == b'blksize':
                try:
                    blksize = max(8, min(65464, int(val)))
                except ValueError:
                    pass
            elif key == b'tsize':
                want_tsize = True
            i += 2

        t = threading.Thread(
            target=_serve_transfer,
            args=(addr, filename, blksize, want_tsize, root),
            daemon=True,
        )
        t.start()


if __name__ == '__main__':
    main()
