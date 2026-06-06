#!/usr/bin/env python3
"""Custom HTTP/1.1 server for GRUB HTTP chunk integration tests.

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

Usage: http_server.py <bind-ip> <port> <root-dir>

Routes:
  /404           Sends only the status line (no blank line), then closes.
                 GRUB's http_establish finds headers_recv=0 when the
                 connection closes and correctly returns GRUB_ERR_FILE_NOT_FOUND.
  /500           Same pattern for 500 Internal Server Error.
  /chunked/<p>   Serve <root>/<p> with Transfer-Encoding: chunked.

Exits with status 1 if it cannot bind, allowing the test's retry loop to
wait for the tap interface to come up before trying again.
"""
import http.server
import os
import sys

_CHUNK_SIZE = 4096


class _Handler(http.server.BaseHTTPRequestHandler):
    root = '.'

    def do_GET(self):
        if self.path == '/404':
            # Send only the status line with no trailing blank line, then
            # close.  GRUB's http_establish checks data->err when
            # headers_recv=0; the early close triggers that path and
            # returns GRUB_ERR_FILE_NOT_FOUND to the caller.
            self.wfile.write(b'HTTP/1.1 404 Not Found\r\n')
            self.wfile.flush()
            self.close_connection = True
            return

        if self.path == '/500':
            self.wfile.write(b'HTTP/1.1 500 Internal Server Error\r\n')
            self.wfile.flush()
            self.close_connection = True
            return

        chunked = self.path.startswith('/chunked/')
        rel = self.path[len('/chunked/'):] if chunked else self.path.lstrip('/')

        root_real = os.path.realpath(self.root)
        full = os.path.realpath(os.path.join(root_real, rel))
        if full != root_real and not full.startswith(root_real + os.sep):
            self.wfile.write(b'HTTP/1.1 403 Forbidden\r\n')
            self.close_connection = True
            return

        try:
            with open(full, 'rb') as fh:
                data = fh.read()
        except FileNotFoundError:
            self.wfile.write(b'HTTP/1.1 404 Not Found\r\n')
            self.close_connection = True
            return
        except OSError:
            self.wfile.write(b'HTTP/1.1 500 Internal Server Error\r\n')
            self.close_connection = True
            return

        if chunked:
            self.send_response(200)
            self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()
            for off in range(0, len(data), _CHUNK_SIZE):
                chunk = data[off:off + _CHUNK_SIZE]
                self.wfile.write(f'{len(chunk):x}\r\n'.encode())
                self.wfile.write(chunk)
                self.wfile.write(b'\r\n')
            self.wfile.write(b'0\r\n\r\n')
            self.wfile.flush()
        else:
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()

    def log_message(self, fmt, *args):
        pass  # suppress per-request log output


def main():
    if len(sys.argv) != 4:
        print(f'Usage: {sys.argv[0]} <bind-ip> <port> <root-dir>',
              file=sys.stderr)
        sys.exit(1)

    bind_ip = sys.argv[1]
    port = int(sys.argv[2])
    _Handler.root = sys.argv[3]

    try:
        server = http.server.HTTPServer((bind_ip, port), _Handler)
    except OSError:
        # Signal to the retry loop that the interface is not ready yet.
        sys.exit(1)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
