import http.server
import socketserver
import ssl

port = 443
host = '0.0.0.0'
handler = http.server.SimpleHTTPRequestHandler

with socketserver.TCPServer((host, port), handler) as httpd:
  httpd.socket = ssl.wrap_socket(httpd.socket,
    certfile='./server.pem', server_side = True)
  print("serving at port", port)
  httpd.serve_forever()