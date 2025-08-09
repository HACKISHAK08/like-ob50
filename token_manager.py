import os
import json
import requests
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

AUTH_URL = "https://token-free-vz9x.vercel.app/get"
MAX_TOKENS = 100
INPUT_FILE = "me_config.json"
OUTPUT_FILE = "me_tokens.json"

def load_accounts(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_tokens(tokens, file_path):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(tokens, f, ensure_ascii=False, indent=4)
    logger.info(f"Saved {len(tokens)} tokens to {file_path}")

def fetch_tokens(accounts):
    session = requests.Session()
    tokens = []
    for user in accounts:
        try:
            params = {'uid': user['uid'], 'password': user['password']}
            response = session.get(AUTH_URL, params=params, timeout=5)
            logger.info(f"Request for {user['uid']} returned status {response.status_code} and response: {response.text}")
            if response.status_code == 200:
                token = response.json().get("token")
                if token:
                    tokens.append({"uid": user['uid'], "token": token})
                    if len(tokens) >= MAX_TOKENS:
                        logger.info(f"Reached max token limit {MAX_TOKENS}, stopping.")
                        break
                else:
                    logger.warning(f"No token in response for {user['uid']}")
            else:
                logger.warning(f"Failed to get token for {user['uid']}, status {response.status_code}")
        except Exception as e:
            logger.error(f"Error fetching token for {user['uid']}: {e}")
    return tokens

def main():
    accounts = load_accounts(INPUT_FILE)
    tokens = fetch_tokens(accounts)
    save_tokens(tokens, OUTPUT_FILE)

if __name__ == "__main__":
    main()