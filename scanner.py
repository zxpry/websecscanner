import requests
import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime

# Security headers we want to check for
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

def normalize_url(url):
    """Make sure the URL has a scheme."""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url

def check_security_headers(url):
    """Check which security headers are present or missing."""
    results = {}
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        headers = response.headers

        for header in SECURITY_HEADERS:
            if header in headers:
                results[header] = {"status": "present", "value": headers[header]}
            else:
                results[header] = {"status": "missing", "value": None}
    except Exception as e:
        results["error"] = str(e)

    return results

def check_https(url):
    """Check if site enforces HTTPS."""
    try:
        http_url = url.replace("https://", "http://")
        response = requests.get(http_url, timeout=10, allow_redirects=False)
        if response.status_code in [301, 302]:
            location = response.headers.get("Location", "")
            if location.startswith("https://"):
                return {"status": "good", "message": "HTTP redirects to HTTPS ✅"}
            else:
                return {"status": "warning", "message": "HTTP redirects but NOT to HTTPS ⚠️"}
        else:
            return {"status": "bad", "message": "Site does not redirect HTTP to HTTPS ❌"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_ssl_certificate(url):
    """Check SSL certificate validity and expiry."""
    try:
        hostname = urlparse(url).hostname
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=hostname
        )
        conn.settimeout(10)
        conn.connect((hostname, 443))
        cert = conn.getpeercert()
        conn.close()

        expire_date_str = cert["notAfter"]
        expire_date = datetime.strptime(expire_date_str, "%b %d %H:%M:%S %Y %Z")
        days_left = (expire_date - datetime.utcnow()).days

        if days_left > 30:
            status = "good"
            message = f"SSL valid, expires in {days_left} days ✅"
        elif days_left > 0:
            status = "warning"
            message = f"SSL expires soon ({days_left} days left) ⚠️"
        else:
            status = "bad"
            message = "SSL certificate has EXPIRED ❌"

        return {"status": status, "message": message, "days_left": days_left}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def check_server_info(url):
    """Check if server leaks version info."""
    try:
        response = requests.get(url, timeout=10)
        server = response.headers.get("Server", None)
        x_powered = response.headers.get("X-Powered-By", None)

        leaks = []
        if server:
            leaks.append(f"Server: {server}")
        if x_powered:
            leaks.append(f"X-Powered-By: {x_powered}")

        if leaks:
            return {"status": "warning", "message": "Server is leaking info ⚠️", "details": leaks}
        else:
            return {"status": "good", "message": "No server info leaked ✅"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def scan(url):
    """Run all checks and return a full report."""
    url = normalize_url(url)

    report = {
        "url": url,
        "scanned_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "https_check": check_https(url),
        "ssl_check": check_ssl_certificate(url),
        "server_info": check_server_info(url),
        "security_headers": check_security_headers(url),
    }

    return report