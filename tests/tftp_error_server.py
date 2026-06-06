#!/usr/bin/env python3
"""TFTP server that responds to every RRQ with a TFTP ERROR packet.

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

Usage: tftp_error_server.py [<bind-ip>]

Exits with status 1 immediately if it cannot bind to UDP port 69, so that
a retry loop in the caller can wait for the tap interface to come up.

Responds to every RRQ with a TFTP ERROR packet (opcode 5, error code 1,
message "File not found").  The reply is sent from an ephemeral UDP socket
to match standard TFTP Transfer Identifier (TID) behaviour, which is
required for GRUB's UDP layer to route the reply to the TFTP callback.
"""
import socket
import struct
import sys
import threading

_TFTP_RRQ   = 1
_TFTP_ERROR = 5

# TFTP ERROR packet: opcode=5, errcode=1 (File not found), message + NUL
_ERROR_PKT = struct.pack('!HH', _TFTP_ERROR, 1) + b'File not found\x00'


def _send_error(client_addr):
    """Send the ERROR packet from a fresh ephemeral socket (server TID)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(('', 0))
        sock.sendto(_ERROR_PKT, client_addr)
    finally:
        sock.close()


def main():
    bind_ip = sys.argv[1] if len(sys.argv) > 1 else ''

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind((bind_ip, 69))
    except OSError:
        sys.exit(1)

    while True:
        try:
            pkt, addr = server_sock.recvfrom(1024)
        except Exception:
            continue
        if len(pkt) < 2:
            continue
        if struct.unpack('!H', pkt[:2])[0] == _TFTP_RRQ:
            threading.Thread(
                target=_send_error, args=(addr,), daemon=True,
            ).start()


if __name__ == '__main__':
    main()
