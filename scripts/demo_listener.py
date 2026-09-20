#!/usr/bin/env python3
"""Synthetic HTTP fixture for all three tiers, including the database tier."""
import http.server
import socket
import sys
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f'{socket.gethostname()} synthetic tier on {sys.argv[2]}\n'.encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
http.server.ThreadingHTTPServer((sys.argv[1], int(sys.argv[2])), Handler).serve_forever()
