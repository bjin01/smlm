import os

import requests
import sys
import json
import urllib3

# Suppress InsecureRequestWarning if verify=False is used for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def run_salt_ping(master_url, username, password, eauth='sharedsecret', target='*'):
    """
    Uses Salt API to perform a test.ping on minions across container boundaries.
    """
    base_url = master_url.rstrip('/')
    login_url = f"{base_url}/login"
    
    # 1. Authenticate and get a token
    login_payload = {
        'username': username,
        'password': password,
        'eauth': eauth
    }

    # Use a session for efficient connection pooling and header management
    with requests.Session() as session:
        try:
            print(f"Authenticating with Salt API at {login_url}...")
            login_response = session.post(login_url, json=login_payload, verify=False)
            login_response.raise_for_status()
            
            token = login_response.json()['return'][0]['token']
            session.headers.update({'X-Auth-Token': token})

            # 2. Execute the test.ping
            print(f"Sending 'saltutil.refresh_pillar' to target: '{target}' via API...")
            salt_payload = [{
                'client': 'local',
                'tgt': target,
                'fun': 'saltutil.refresh_pillar',
                'arg': ["wait=False"]
            }]
            
            response = session.post(base_url, json=salt_payload, verify=False)
            response.raise_for_status()
            
            # Salt API returns a list with a dictionary of results
            results = response.json().get('return', [{}])[0]

            if not results:
                print("No response from minions. Verify salt-api permissions and minion status.")
                return

            print("\nResults:")
            for minion_id, success in results.items():
                status = "Done" if success else "Failed"
                print(f" - {minion_id}: {status}")

        except requests.exceptions.RequestException as e:
            print(f"API Connection Error: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Unexpected error parsing API response: {e}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    # Adjust these values to match your environment
    salt_master = os.getenv('SALT_MASTER', 'uyuni-server.mgr.internal')
    salt_master_tornado_port = os.getenv('SALT_API_PORT', '8000')  # Default to 8000 if not set
    username = os.getenv('SALT_API_USER', 'salt')
    password = os.getenv('SALT_API_SECRET', '')
    run_salt_ping(master_url=f'http://{salt_master}:{salt_master_tornado_port}', username=username, password=password)
