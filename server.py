import http.server
import socketserver
import os

PORT = 9999

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        field_data = self.rfile.read(content_length)
        filename = self.headers['Filename']
        with open(filename, 'wb') as output_file:
            output_file.write(field_data)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'File uploaded successfully')
        

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), CustomHTTPRequestHandler) as httpd:
        print(f"Serving at port {PORT}")
        httpd.serve_forever()
