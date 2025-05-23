from flask import Flask, jsonify, request
import time
import os
import requests # To simulate checking DNS for upstream
import socket

app = Flask(__name__)

# In a real scenario, this would be fetched securely
current_nhi = "initial_secret_abcdef123"
static_fallback_nhi = "STATIC_BREAK_GLASS_KEY_XYZABC" # This is the target for capture
last_rotation_time = time.time()

def check_dns_resolution(hostname="google.com"):
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.gaierror:
        return False

@app.route('/rotate_secret', methods=['POST'])
def rotate_secret():
    global current_nhi, last_rotation_time
    print(f"[{time.time()}] /rotate_secret called. DNS status: {check_dns_resolution()}")

    # Simulate DNS-dependent upstream call for rotation
    if not check_dns_resolution(os.getenv('MOCK_DNS_SERVER', 'google.com')): # Or some other internal service name
        print("DNS resolution failed. Cannot contact upstream for rotation.")
        return jsonify({"status": "failed", "message": "DNS resolution error, rotation failed"}), 500
    
    # Simulate successful rotation
    new_secret = f"rotated_secret_{time.time()}"
    current_nhi = new_secret
    last_rotation_time = time.time()
    print(f"Secret rotated successfully to: {current_nhi}")
    return jsonify({"status": "success", "new_secret": current_nhi}), 200

@app.route('/get_secret', methods=['GET'])
def get_secret():
    print(f"[{time.time()}] /get_secret called. DNS status: {check_dns_resolution()}")
    # This part should be secured, but for PoC we show it.
    # In a real scenario, the client would need to authenticate to get this.
    # Here, we're simulating the *client* trying to get the secret, and if rotation fails,
    # it might fall back to a hardcoded or previously fetched 'static_fallback_nhi'
    if not check_dns_resolution(os.getenv('MOCK_DNS_SERVER', 'google.com')) and (time.time() - last_rotation_time > 60): # If DNS is down for too long
        print(f"DNS down and rotation failed for too long. Providing static fallback secret: {static_fallback_nhi}")
        # This is where the 'plaintext' exposure could happen if the client is vulnerable
        # E.g., if a legacy client simply hardcodes this and logs it, or exposes via debugging
        return jsonify({"status": "fallback", "secret": static_fallback_nhi}), 200
    
    print(f"Providing current secret: {current_nhi}")
    return jsonify({"status": "active", "secret": current_nhi}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8200)
