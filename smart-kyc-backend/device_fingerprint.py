import hashlib
import datetime
from flask import request

def get_device_info():
    """
    Captures user agent, browser, platform, and IP address from the Flask request object.
    Generates a unique SHA256 hash representing the device.
    """
    ua = request.user_agent

    browser = f"{ua.browser} {ua.version}"
    platform = ua.platform
    user_agent = request.headers.get("User-Agent", "unknown")

    # Local IP (Handling X-Forwarded-For for proxied requests)
    if request.headers.getlist("X-Forwarded-For"):
        ip_addr = request.headers.getlist("X-Forwarded-For")[0]
    else:
        ip_addr = request.remote_addr

    # Raw string to hash
    device_raw = f"{browser}-{platform}-{ip_addr}-{user_agent}"

    # Create unique device hash
    device_hash = hashlib.sha256(device_raw.encode()).hexdigest()

    return {
        "browser": browser,
        "platform": platform,
        "ip": ip_addr,
        "user_agent": user_agent,
        "device_hash": device_hash,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }