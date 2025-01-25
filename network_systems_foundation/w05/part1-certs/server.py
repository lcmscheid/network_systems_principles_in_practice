#!/usr/bin/python3

import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl


class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'123')


def main(dir):
   httpd = HTTPServer(('localhost', 4443), SimpleHTTPRequestHandler)
   httpd.socket = ssl.wrap_socket(httpd.socket, keyfile=dir+"/webserver-private.pem", certfile=dir+'/webserver-cert.pem', server_side=True)
   httpd.serve_forever()


if __name__ == '__main__':
    main(".")
