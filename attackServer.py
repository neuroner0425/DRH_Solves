from http.server import SimpleHTTPRequestHandler, HTTPServer

class StealHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        print("Data received:", self.path)  #
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

httpd = HTTPServer(('0.0.0.0', 8080), StealHandler)  # 8080
print("Listening on port 8080...")
httpd.serve_forever()
