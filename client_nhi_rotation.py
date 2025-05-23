# client_nhi_rotation.py - Simulates a client rotating its NHI
import requests
import time
import os

SECRETS_MANAGER_URL = os.getenv('SECRETS_MANAGER_URL', 'http://mock_secrets_manager:8200') # Use Docker service name

def get_and_rotate_nhi():
    current_nhi = None
    retry_count = 0
    max_retries = 10
    backoff_time = 5 # seconds

    while retry_count < max_retries:
        try:
            print(f"[Client] Attempting to get/rotate secret (retry {retry_count}/{max_retries})...")
            response = requests.post(f"{SECRETS_MANAGER_URL}/rotate_secret", timeout=5)
            data = response.json()

            if response.status_code == 200 and data.get("status") == "success":
                current_nhi = data.get("new_secret")
                print(f"[Client] Successfully rotated and obtained new NHI: {current_nhi}")
                return current_nhi # Success
            elif response.status_code == 500: # Simulated DNS error
                print(f"[Client] Rotation failed (DNS error simulation). Message: {data.get('message')}")
                # Fallback to static if DNS down for too long - this is where the vulnerability lies
                fallback_response = requests.get(f"{SECRETS_MANAGER_URL}/get_secret", timeout=5)
                fallback_data = fallback_response.json()
                if fallback_response.status_code == 200 and fallback_data.get("status") == "fallback":
                    print(f"[Client] Falling back to static NHI: {fallback_data.get('secret')}")
                    # In a vulnerable client, this might be logged, or even used in a way that tcpdump can see
                    return fallback_data.get('secret') # This is the key we want to see captured

            else:
                print(f"[Client] Rotation failed with unexpected status {response.status_code}: {data}")

        except requests.exceptions.ConnectionError as e:
            print(f"[Client] Connection error during rotation: {e}. Retrying...")
        except requests.exceptions.Timeout:
            print("[Client] Request timed out. Retrying...")
        except Exception as e:
            print(f"[Client] An unexpected error occurred: {e}")

        retry_count += 1
        time.sleep(backoff_time)
        backoff_time *= 1.5 # Exponential backoff

    print("[Client] Max retries reached. Could not obtain active NHI.")
    return None

if __name__ == '__main__':
    print("--- NHI Client Simulation Started ---")
    stolen_key = get_and_rotate_nhi()
    if stolen_key:
        print(f"[Client] NHI ultimately used/exposed: {stolen_key}")
    else:
        print("[Client] Failed to get any NHI after retries.")
    print("--- NHI Client Simulation Complete ---")
