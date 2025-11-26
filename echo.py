from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime

LOGFILE = "/tmp/requests.log"   # change path if you prefer

class H(BaseHTTPRequestHandler):
    def _reply(self):
        # Prepare response
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()

        # Compose a string of what we’ll both return and log
        lines = []
        lines.append(f"{self.command} {self.path} {self.request_version}")
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")  # blank line after headers
        body = "\n".join(lines)

        # Send back to client
        self.wfile.write(body.encode())

        # Append to logfile with timestamp
        try:
            with open(LOGFILE, "a", encoding="utf-8") as f:
                f.write(f"\n[{datetime.utcnow().isoformat()} UTC]\n")
                f.write(body)
                f.write("\n" + "-"*60 + "\n")
        except Exception as e:
            # If log file write fails, print to stderr (server console)
            print(f"Log write error: {e}")

    def do_GET(self):
        self._reply()

    def do_POST(self):
        self._reply()

    def log_message(self, fmt, *args):
        # Disable built-in HTTPServer logging to stderr
        return

if __name__ == "__main__":
    print(f"Listening on http://127.0.0.1:8080, logging to {LOGFILE}")
    HTTPServer(("127.0.0.1", 8080), H).serve_forever()
