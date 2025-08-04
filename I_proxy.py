

import http.server
import socketserver
import requests
import select
import os
import socket
import hashlib
import base64
import time
import threading 

from retry import retry 
from collections import defaultdict, Counter 
from urllib.parse import urlparse
from datetime import datetime, timedelta
from email.utils import parsedate_to_datetime


PORT = 8070


LOCAL_BLOCKED_SITES = [ # Renamed to distinguish from dynamic
    "example.com",
    "ads.google.com",
    "badwebsite.io",
]

DYNAMIC_BLOCKED_SITES = set() # New list for dynamically fetched malicious sites

CACHE = {}

AUTHORIZED_USERS = {
    "admin": "password123", # replace with secure values later
}

# fetch dynamic blocked sites
@retry(requests.exceptions.RequestException, tries=3, delay=10)
def fetch_blocked_sites_list():
    """Fetches the blocked sites list with retries."""
    url = "https://adaway.org/hosts.txt" # Using the alternative link
    response = requests.get(url, timeout=30)
    return response

def update_blocked_sites():
    print("Updating dynamic blocked sites list...")
    try:
        response = fetch_blocked_sites_list()
        
        new_blocked_sites = set()
        for line in response.text.splitlines():
            if line.startswith("0.0.0.0") or line.startswith("127.0.0.1"):
                parts = line.split()
                if len(parts) > 1 and not parts[1].startswith("#"):
                    new_blocked_sites.add(parts[1])

        global DYNAMIC_BLOCKED_SITES
        DYNAMIC_BLOCKED_SITES = new_blocked_sites
        print(f"Updated with {len(DYNAMIC_BLOCKED_SITES)} blocked sites.")
        
    except requests.exceptions.RequestException as e:
        print(f"Failed to update blocked sites after multiple retries: {e}")

    threading.Timer(86400, update_blocked_sites).start() # Schedule next update

# Call it once at startup
update_blocked_sites()


class Proxyhandler(http.server.BaseHTTPRequestHandler):

    REQUEST_LOG = defaultdict(list)
    RATE_LIMIT = 100 # Max 10 requests per minute

    CACHE_DIR = "cache"
    os.makedirs(CACHE_DIR, exist_ok=True)

    protocol_version = "HTTP/1.1"

    # New detailed log to store dictionaries for analytics
    DETAILED_REQUEST_LOG = [] 
    
    # New list of keywords to filter
    MALICIOUS_KEYWORDS = ['malware', 'phishing', 'virus', 'trojan']

    # should also be a static method of the class
    @staticmethod
    def anonymize_headers(headers):
        sensitive = ['User-Agent', 'Referer', 'Cookie', 'X-Forwarded-For']
        new_headers = {}
        for k, v in headers.items():
            if k not in sensitive:
                new_headers[k] = v
        new_headers["User-Agent"] = "I-ProxyBot/1.0"
        return new_headers


    @staticmethod
    def get_expiration(headers):
        # Check Cache-Control header
        cache_control = headers.get("Cache-Control", "")
        directives = [d.strip().lower() for d in cache_control.split(",")]

        for directive in directives:
            if directive.startswith("max-age="):
                try:
                    seconds = int(directive.split("=")[1])
                    return datetime.utcnow() + timedelta(seconds=seconds)
                except ValueError:
                    pass 

            elif directive in ("no-cache", "no-store"):
                return None

        # If no Cache-Control, fall back to Expires header
        expires = headers.get("Expires")
        if expires:
            try:
                return parsedate_to_datetime(expires).replace(tzinfo=None)
            except Exception:
                pass

        content_type = headers.get("Content-Type", "").lower()
        
        # Cache images for longer
        if "image/" in content_type:
            print("Applying heuristic: caching image for 12 hours.")
            return datetime.utcnow() + timedelta(hours=12)
        
        # Cache other static assets for a small amount of time
        if "javascript" in content_type or "css" in content_type:
            print("Applying heuristic: caching script/stylesheet for 1 hour.")
            return datetime.utcnow() + timedelta(hours=1)

        # Fallback for dynamic content (or if no headers found)
        print("Applying heuristic: caching other content for 1 minute.")
        return datetime.utcnow() + timedelta(seconds=60)

    def get_cache_filename(self, url):
        hashed = hashlib.sha256(url.encode()).hexdigest()
        return os.path.join(self.CACHE_DIR, hashed)

    def save_to_cache(self, url, response_bytes):
        with open(self.get_cache_filename(url), "wb") as f:
            f.write(response_bytes)

    def load_from_cache(self,url):
        try:
            with open(self.get_cache_filename(url), "rb") as f:
                return f.read()
        except FileNotFoundError:
            return None

    def _TUNNEL(self, client_sock, remote_sock):
        sockets = [client_sock, remote_sock]

        try:
            while True:
                readable, _, _ = select.select(sockets, [], [])
                for sock in readable:
                    other = remote_sock if sock is client_sock else client_sock
                    data = sock.recv(4096)
                    if not data:
                        return #Tunnel closed
                    other.sendall(data)

        finally:
            remote_sock.close()
            client_sock.close()

    def is_rate_limited(self, client_ip):
        now = time.time()
        logs = self.REQUEST_LOG[client_ip]

        #removing old entries
        self.REQUEST_LOG[client_ip] = [t for t in logs if now-t< 60]

        if len(self.REQUEST_LOG[client_ip])> self.RATE_LIMIT:
            return True
        self.REQUEST_LOG[client_ip].append(now)
        return False

    def is_authorized(self):
        # Check for Proxy-Authorization header (for proxied requests)
        auth = self.headers.get("Proxy-Authorization")
        
        # If not found, check for the standard Authorization header (for direct requests like /admin)
        if not auth:
            auth = self.headers.get("Authorization")

        if not auth or not auth.startswith("Basic"):
            return False

        decoded = base64.b64decode(auth[6:]).decode()
        username, password = decoded.split(":", 1)
        return AUTHORIZED_USERS.get(username) == password

    def do_CONNECT(self):
        # if not self.is_authorized():
        #     self.send_response(401)
        #     self.send_header("WWW-Authenticate", 'Basic realm="I-Proxy Access"')
        #     self.end_headers()
        #     return

        full_url = self.path
        if not self.path.startswith("https"):
            host = self.headers.get("Host")
            full_url = f"https://{host}{self.path}"

        parsed_url = urlparse(full_url)
        hostname = parsed_url.hostname

                # loop check for inifinte stuff
        requested_host_header = self.headers.get("Host")
        # Ensure PORT is correctly used and matches the global PORT
        proxy_address = f"localhost:{PORT}"
        proxy_address_ip = f"127.0.0.1:{PORT}"

        
        
        # Check if the Host header points to the proxy itself
        if requested_host_header == proxy_address or requested_host_header == proxy_address_ip:
            print(f"DEBUG: Loop detected via Host header: {requested_host_header}")
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>Loop detected: request to proxy itself is blocked</h1>")
            return

        if hostname in LOCAL_BLOCKED_SITES or hostname in DYNAMIC_BLOCKED_SITES:
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>This site is blocked by I-Proxy</h1>")
            return

        client_ip = self.client_address[0]
        if self.is_rate_limited(client_ip):
            self.send_error(429, "Too Many Requests")
            return

        host, port = self.path.split(":")
        port = int(port)
        
        try:
            remote_sock = socket.create_connection((host, port))
            self.send_response(200, "Connection Established")
            self.end_headers()

            self._TUNNEL(self.connection, remote_sock)

        except Exception as e:
            self.send_error(502, f"Bad Gateway: {e}")
            print(f"Tunnel error: {e}")

    def clean_up_logs(self):
        """Removes log entries older than 60 seconds from DETAILED_REQUEST_LOG."""
        now = datetime.now()
        self.DETAILED_REQUEST_LOG = [
            entry for entry in self.DETAILED_REQUEST_LOG 
            if (now - entry['timestamp']) < timedelta(seconds=60)
        ]

    def do_GET(self):
        # 1. Authentication Check (currently commented out)
        # if not self.is_authorized():
        #     self.send_response(401)
        #     self.send_header("WWW-Authenticate", 'Basic realm="I-Proxy Access"')
        #     self.end_headers()
        #     return
        
        # 2. Rate Limiting Check
        client_ip = self.client_address[0]
        if self.is_rate_limited(client_ip):
            self.send_error(429, "Too Many Requests")
            return

        # Build full_url early for logging and other checks
        full_url = self.path
        if not self.path.startswith("http"):
            host = self.headers.get("Host")
            full_url = f"http://{host}{self.path}"

        # Clean up and log the request for analytics
        self.clean_up_logs()
        self.DETAILED_REQUEST_LOG.append({
            'ip': client_ip,
            'url': full_url,
            'timestamp': datetime.now()
        })

        print(f"Client IP: {client_ip}")
        print(f"Requested Path: {self.path}")
        print("Requested Headers: ")
        for key, value in self.headers.items():
            print(f" {key}: {value}")

        # dashboard for like the urls and all(remember to add this)
        if self.path.startswith("/admin"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()

            active_ips_count = len(self.REQUEST_LOG)
            total_requests_count = len(self.DETAILED_REQUEST_LOG)
            
            url_counts = Counter(entry['url'] for entry in self.DETAILED_REQUEST_LOG)
            
            top_sites_list = ""
            # Start of improved dashboard HTML
            dashboard = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>I-Proxy Dashboard</title>
                <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
                <script src="https://cdn.tailwindcss.com"></script>
                <style>
                    body {{
                        font-family: 'Inter', sans-serif;
                    }}
                </style>
            </head>
            <body class="bg-gray-100 p-4 sm:p-8">
                <div class="max-w-4xl mx-auto bg-white shadow-lg rounded-xl p-6 sm:p-8">
                    <h1 class="text-3xl sm:text-4xl font-bold text-center text-gray-800 mb-6">I-Proxy Dashboard 🚀</h1>
                    
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
                        <div class="bg-blue-50 p-5 rounded-lg shadow-sm">
                            <h2 class="text-xl font-semibold text-blue-700 mb-2">Active Users</h2>
                            <p class="text-3xl font-bold text-blue-900">{active_ips_count}</p>
                            <p class="text-sm text-gray-600">Unique IPs in last 60 seconds</p>
                        </div>
                        <div class="bg-green-50 p-5 rounded-lg shadow-sm">
                            <h2 class="text-xl font-semibold text-green-700 mb-2">Total Requests</h2>
                            <p class="text-3xl font-bold text-green-900">{total_requests_count}</p>
                            <p class="text-sm text-gray-600">Requests in last 60 seconds</p>
                        </div>
                    </div>

                    <div class="bg-purple-50 p-6 rounded-lg shadow-sm">
                        <h2 class="text-xl font-semibold text-purple-700 mb-4">Top 5 Visited Sites (Last 60s)</h2>
                        <ul class="space-y-3">
                            {top_sites_list}
                        </ul>
                        {no_requests_message}
                    </div>
                </div>
            </body>
            </html>
            """
            
            if url_counts:
                for url, count in url_counts.most_common(5):
                    top_sites_list += f"""
                    <li class="flex items-center justify-between p-3 bg-white rounded-md shadow-xs">
                        <span class="text-gray-800 text-sm md:text-base truncate">{url}</span>
                        <span class="ml-4 px-3 py-1 bg-purple-200 text-purple-800 text-sm font-semibold rounded-full">{count} visits</span>
                    </li>
                    """
                no_requests_message = ""
            else:
                no_requests_message = "<p class='text-center text-gray-600 mt-4'>No requests yet. Start browsing!</p>"
                top_sites_list = "" # Ensure list is empty if no requests

            # Format the dashboard string with dynamic content
            dashboard = dashboard.format(
                active_ips_count=active_ips_count,
                total_requests_count=total_requests_count,
                top_sites_list=top_sites_list,
                no_requests_message=no_requests_message
            )

            self.wfile.write(dashboard.encode())
            return

        # loop check for inifinte stuff
        requested_host_header = self.headers.get("Host")
        # Ensure PORT is correctly used and matches the global PORT
        proxy_address = f"localhost:{PORT}"
        proxy_address_ip = f"127.0.0.1:{PORT}"

        
        
        # Check if the Host header points to the proxy itself
        if requested_host_header == proxy_address or requested_host_header == proxy_address_ip:
            print(f"DEBUG: Loop detected via Host header: {requested_host_header}")
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>Loop detected: request to proxy itself is blocked</h1>")
            return
        #

        # Parse URL for hostname for other checks (after the Host header loopback check)
        parsed_url = urlparse(full_url)
        hostname = parsed_url.hostname

        # Check for General Blocked Sites (Static and Dynamic)
        
        if hostname in LOCAL_BLOCKED_SITES or hostname in DYNAMIC_BLOCKED_SITES:
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>This site is blocked by I-Proxy</h1>")
            return

        # Disk Cache Check
        cached_response = self.load_from_cache(full_url)
        if cached_response:
            print(f"Serving {full_url} from disk cache")
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(cached_response)
            return

        # Apply Content Filtering
        try:
            # Use the static method for anonymizing heade-rs
            headers = self.anonymize_headers(self.headers) 
            
            # Print the full_url that requests.get is about to use for debugging
            print(f"DEBUG: Attempting to fetch URL: {full_url}")

            response = requests.get(full_url, headers=headers, timeout=5)
            
            # Content-aware filtering
            response_text = response.text.lower()
            if any(keyword in response_text for keyword in self.MALICIOUS_KEYWORDS):
                print(f"Content blocked: Malicious keyword detected on {full_url}")
                self.send_response(403)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<h1>Content blocked by I-Proxy: Malicious keyword detected.</h1>")
                return

            # Save to cache if status code is 200
            if response.status_code == 200:
                self.save_to_cache(full_url, response.content)

            expires_at = self.get_expiration(response.headers)
            if expires_at:
                CACHE[full_url] = {
                    "expires_at": expires_at,
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.content,
                }
            
            # Sending the response back to the client
            self.send_response(response.status_code)
            for k,v in response.headers.items():
                if k.lower() not in ["set-cookie", "transfer-encoding"]:
                    self.send_header(k,v)

            self.end_headers()
            self.wfile.write(response.content)

        except requests.exceptions.RequestException as e:
            self.send_error(502, f"Upstream error: {e}")

    def is_loopback_request(self): # This function is now redundant for do_GET but kept for do_POST
        parsed_url = urlparse(self.path)
        return parsed_url.hostname in ["localhost", "127.0.0.1"] and parsed_url.port == PORT


    def filter_headers(self, headers):
        return {k: v for k, v in headers.items() if k.lower() not in ["host", "content-length"]}

    #POST method
    def do_POST(self):
        client_ip = self.client_address[0]
        if not self.is_authorized():
            self.send_error(403, "Forbidden")
            return

        if self.is_rate_limited(client_ip): 
            self.send_error(429, "Too Many Requests")
            return

        if self.is_loopback_request():
            self.send_error(403, "Forbidden (loopback)")
            return

        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        parsed_url = urlparse(self.path)
        hostname = parsed_url.hostname or self.headers.get("Host")
        if not hostname:
            self.send_error(400, "Bad Request: No Host")
            return

        if hostname in LOCAL_BLOCKED_SITES or hostname in DYNAMIC_BLOCKED_SITES: # Use LOCAL_BLOCKED_SITES here too
            self.send_error(403, "Forbidden (domain blocked)")
            return

        try:
            # Use requests.post for consistency and better error handling
            response = requests.post(self.path, headers=self.anonymize_headers(self.headers), data=post_data, timeout=5)

            self.send_response(response.status_code)
            for key, value in response.headers.items():
                if key.lower() not in ["set-cookie", "transfer-encoding"]: # Filter headers for POST too
                    self.send_header(key, value)
            self.end_headers()
            self.wfile.write(response.content)
        except requests.exceptions.RequestException as e:
            self.send_error(500, f"Internal Server Error: {e}")


with socketserver.ThreadingTCPServer(("", PORT), Proxyhandler) as httpd:
    print(f"Proxy Server running on port {PORT}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down proxy...")
        httpd.shutdown()
