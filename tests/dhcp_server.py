#!/usr/bin/env python3
"""Minimal DHCP/BOOTP server for GRUB network integration tests.

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

Usage: dhcp_server.py [--bootp] <server-ip> <offered-ip>

Without --bootp (default): handles a DHCP exchange
  (DISCOVER -> OFFER -> REQUEST -> ACK) and then continues serving
  retransmissions until killed.

With --bootp: emits a bare BOOTP reply (RFC 951) in response to every
  BOOTREQUEST.  The reply includes vendor extensions (magic cookie, subnet
  mask, router, hostname) but deliberately omits option 53 (DHCP message
  type).  This exercises bootp.c line 647: the type == GRUB_DHCP_MESSAGE_UNKNOWN
  branch that fires when no option 53 is present in the server reply.

Both modes bind to tap0 via SO_BINDTODEVICE and exit with status 1 when
the interface is not yet up; the test retry loop uses this to wait for
qemu-linkup.

Options included in DHCP ACK / BOOTP reply:
  1  Subnet Mask     255.255.255.0
  3  Router          <server-ip>
  12 Hostname        grub-test-host
  51 IP Lease Time   3600  (DHCP mode only)
  54 Server ID       <server-ip>  (DHCP mode only)
"""
import signal
import socket
import struct
import sys

# BOOTP opcodes
_BOOTREQUEST = 1
_BOOTREPLY = 2

# DHCP message types (option 53)
_DHCP_DISCOVER = 1
_DHCP_OFFER = 2
_DHCP_REQUEST = 3
_DHCP_ACK = 5

# RFC 1048 magic cookie
_MAGIC_COOKIE = b'\x63\x82\x53\x63'

# BOOTP/DHCP fixed header (236 bytes):
#   opcode, hw_type, hw_len, gate_hops, ident, seconds, flags,
#   ciaddr, yiaddr, siaddr, giaddr, chaddr(16), sname(64), file(128)
_HEADER = struct.Struct('!BBBBIHH4s4s4s4s16s64s128s')

_LEASE_SECS = 3600
_TEST_HOSTNAME = b'grub-test-host'


def _opt(code, data):
    return bytes([code, len(data)]) + data


def _pad(data: bytes, size: int) -> bytes:
    """Return *data* truncated or null-padded to exactly *size* bytes."""
    return data[:size].ljust(size, b'\x00')


def _build_reply(xid, chaddr6, your_ip_bytes, server_ip_bytes, msg_type,
                 extra_opts=b'', sname=b'', boot_file=b''):
    chaddr = chaddr6 + b'\x00' * (16 - len(chaddr6))
    opts = (
        _MAGIC_COOKIE
        + _opt(53, bytes([msg_type]))
        + _opt(54, server_ip_bytes)
        + _opt(51, struct.pack('!I', _LEASE_SECS))
        + _opt(1, b'\xff\xff\xff\x00')  # subnet mask 255.255.255.0
        + extra_opts
        + bytes([255])  # END
    )
    header = _HEADER.pack(
        _BOOTREPLY, 1, 6, 0,           # opcode, hw_type, hw_len, gate_hops
        xid,                            # ident (XID)
        0, 0,                           # seconds, flags
        b'\x00\x00\x00\x00',           # ciaddr
        your_ip_bytes,                  # yiaddr
        server_ip_bytes,                # siaddr
        b'\x00\x00\x00\x00',           # giaddr
        chaddr,                         # chaddr (16 bytes)
        _pad(sname, 64),                # sname (fixed BOOTP field, option 66 fallback)
        _pad(boot_file, 128),           # file  (fixed BOOTP field, option 67 fallback)
    )
    return header + opts


def _build_bootp_reply(xid, chaddr6, your_ip_bytes, server_ip_bytes):
    """Build a bare BOOTP reply — no option 53 (DHCP message type).

    Exercises bootp.c line 647: type == GRUB_DHCP_MESSAGE_UNKNOWN branch.
    Vendor extensions (magic cookie, subnet mask, router, hostname) are
    included so grub_net_configure_by_dhcp_ack can still parse them; only
    option 53 is absent, which is what makes GRUB treat this as pure BOOTP.
    """
    chaddr = chaddr6 + b'\x00' * (16 - len(chaddr6))
    opts = (
        _MAGIC_COOKIE
        + _opt(1, b'\xff\xff\xff\x00')   # subnet mask 255.255.255.0
        + _opt(3, server_ip_bytes)        # router
        + _opt(12, _TEST_HOSTNAME)        # hostname
        + bytes([255])                    # END
    )
    header = _HEADER.pack(
        _BOOTREPLY, 1, 6, 0,             # opcode, hw_type, hw_len, gate_hops
        xid,                             # ident (XID)
        0, 0,                            # seconds, flags
        b'\x00\x00\x00\x00',            # ciaddr
        your_ip_bytes,                   # yiaddr
        server_ip_bytes,                 # siaddr
        b'\x00\x00\x00\x00',            # giaddr
        chaddr,                          # chaddr (16 bytes)
        b'\x00' * 64,                    # sname
        b'\x00' * 128,                   # file
    )
    return header + opts


def _parse_msg_type(vendor):
    if len(vendor) < 5 or vendor[:4] != _MAGIC_COOKIE:
        return None
    i = 4
    while i < len(vendor) - 1:
        code = vendor[i]
        if code == 0:        # PAD
            i += 1
            continue
        if code == 255:      # END
            break
        if i + 1 >= len(vendor):
            break
        length = vendor[i + 1]
        if code == 53 and length >= 1 and i + 2 < len(vendor):
            return vendor[i + 2]
        i += 2 + length
    return None


def main():
    bootp_mode = '--bootp' in sys.argv

    # Strip flags and collect keyword args (--sname=VALUE, --file=VALUE).
    sname_field = b''
    file_field  = b''
    positional  = []
    for a in sys.argv[1:]:
        if a == '--bootp':
            pass
        elif a.startswith('--sname='):
            sname_field = a[len('--sname='):].encode()
        elif a.startswith('--file='):
            file_field = a[len('--file='):].encode()
        else:
            positional.append(a)

    if len(positional) != 2:
        print(f'Usage: {sys.argv[0]} [--bootp] [--sname=NAME] [--file=PATH]'
              ' <server-ip> <offered-ip>', file=sys.stderr)
        sys.exit(1)

    server_ip = positional[0]
    offered_ip = positional[1]
    server_ip_bytes = socket.inet_aton(server_ip)
    offered_ip_bytes = socket.inet_aton(offered_ip)

    # Router and hostname options included in DHCP ACK
    ack_extra = (
        _opt(3, server_ip_bytes)        # router
        + _opt(12, _TEST_HOSTNAME)      # hostname
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # SO_BINDTODEVICE limits the socket to tap0 and causes setsockopt to
    # return ENODEV when tap0 does not exist yet.  The test retry loop relies
    # on this early-exit to know that the tap interface is not ready.
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'tap0\0')
    except OSError:
        sys.exit(1)

    try:
        sock.bind(('', 67))
    except OSError:
        sys.exit(1)

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    # active_mac: chaddr of the client we are currently serving.
    # active_xid: XID of the most-recently OFFERed transaction.
    # We lock to the first DISCOVER's MAC so that any other DHCP client that
    # happens to send on tap0 (e.g. NetworkManager probing the new interface)
    # does not receive our test offer and does not displace the GRUB guest.
    active_mac = None
    active_xid = None

    while True:
        try:
            data, _addr = sock.recvfrom(4096)
        except OSError:
            break

        if len(data) < _HEADER.size:
            continue

        fields = _HEADER.unpack(data[:_HEADER.size])
        opcode = fields[0]
        xid = fields[4]
        chaddr6 = fields[11][:6]
        vendor = data[_HEADER.size:]

        if opcode != _BOOTREQUEST:
            continue

        if bootp_mode:
            # Pure BOOTP (RFC 951): reply immediately to every BOOTREQUEST
            # without option 53.  No handshake — one request → one reply.
            reply = _build_bootp_reply(xid, chaddr6, offered_ip_bytes,
                                       server_ip_bytes)
            sock.sendto(reply, ('255.255.255.255', 68))
            continue

        msg_type = _parse_msg_type(vendor)

        if msg_type == _DHCP_DISCOVER:
            # Ignore DISCOVERs from MACs other than the one we already locked
            # in.  This prevents the server from responding to any host-side
            # DHCP client that may probe tap0 (SO_BINDTODEVICE already filters
            # other interfaces, but not other clients on the same tap).
            if active_mac is not None and chaddr6 != active_mac:
                continue
            active_mac = chaddr6
            active_xid = xid
            reply = _build_reply(xid, chaddr6, offered_ip_bytes,
                                 server_ip_bytes, _DHCP_OFFER)
            sock.sendto(reply, ('255.255.255.255', 68))

        elif msg_type == _DHCP_REQUEST and xid == active_xid and chaddr6 == active_mac:
            reply = _build_reply(xid, chaddr6, offered_ip_bytes,
                                 server_ip_bytes, _DHCP_ACK, ack_extra,
                                 sname=sname_field, boot_file=file_field)
            sock.sendto(reply, ('255.255.255.255', 68))


if __name__ == '__main__':
    main()
