from eth_account import Account
from eth_account.messages import encode_defunct
from curl_cffi import requests
from datetime import datetime, timezone
import os
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor
import threading
import time
import random
import json
import base58
import argparse

# Configuration
THREAD_COUNT = 2  # Reduced number of concurrent threads
MIN_DELAY = 3  # Minimum delay between requests in seconds
MAX_DELAY = 5  # Maximum delay between requests in seconds

# Lock to ensure output is not mixed up
print_lock = threading.Lock()

# Initialize colorama
init()

def safe_print(message):
    with print_lock:
        print(message)

def log_success(message):
    safe_print(f"{Fore.GREEN}{message}{Style.RESET_ALL}")

def log_error(message):
    safe_print(f"{Fore.RED}{message}{Style.RESET_ALL}")

def log_info(message):
    safe_print(f"{Fore.CYAN}{message}{Style.RESET_ALL}")

def random_delay():
    """Add a random delay between requests to avoid rate limiting"""
    delay = random.uniform(MIN_DELAY, MAX_DELAY)
    time.sleep(delay)

def append_to_result(wallet, total, unclaimed, chain):
    with print_lock:
        with open('results.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{chain}] {wallet}: Airdrop amount: {total}, Unclaimed amount: {unclaimed}\n")

def sign_message_evm(private_key, message):
    """Sign a message with an Ethereum private key"""
    account = Account.from_key(private_key)
    message_encoded = encode_defunct(text=message)
    signed_message = account.sign_message(message_encoded)
    return "0x" + signed_message.signature.hex(), account.address

def sign_message_solana(private_key_base58, message):
    """Sign a message with a Solana private key using solders"""
    try:
        from solders.keypair import Keypair
        import base58
        
        # Convert private key to bytes - handle both formats
        try:
            # First try direct base58 decode
            private_key_bytes = base58.b58decode(private_key_base58)
            if len(private_key_bytes) != 64:  # Not a full keypair
                # Try as a 32-byte secret key
                if len(private_key_bytes) == 32:
                    # Expand to full keypair bytes
                    keypair = Keypair.from_seed(private_key_bytes)
                    private_key_bytes = keypair.to_bytes()
                else:
                    raise ValueError(f"Invalid private key length: {len(private_key_bytes)}")
        except Exception:
            # If that fails, try hex decode
            try:
                if private_key_base58.startswith('0x'):
                    private_key_base58 = private_key_base58[2:]
                private_key_bytes = bytes.fromhex(private_key_base58)
                if len(private_key_bytes) == 32:
                    keypair = Keypair.from_seed(private_key_bytes)
                    private_key_bytes = keypair.to_bytes()
                else:
                    raise ValueError(f"Invalid hex private key length: {len(private_key_bytes)}")
            except Exception as e:
                raise ValueError(f"Could not decode private key: {str(e)}")
        
        # Create keypair from the full keypair bytes
        keypair = Keypair.from_bytes(private_key_bytes)
        
        # Sign the message
        message_bytes = message.encode('utf-8')
        signature = keypair.sign_message(message_bytes)
        
        # Convert signature to hex string with 0x prefix (API expects this format)
        signature_bytes = bytes(signature)  # Convert signature to bytes
        signature_hex = "0x" + signature_bytes.hex()  # Convert bytes to hex
        
        # Return the signature and public key
        return signature_hex, str(keypair.pubkey())
        
    except Exception as e:
        log_error(f"Error signing Solana message: {str(e)}")
        return None, None

def get_auth_message():
    try:
        random_delay()
        url = "https://api.clusters.xyz/v0.1/airdrops/pengu/auth/message"
        headers = {
            "accept": "*/*",
            "accept-language": "en-GB,en-US;q=0.9,en;q=0.8",
            "priority": "u=1, i",
            "sec-ch-ua": '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"macOS"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "cross-site",
            "Referer": "https://claim.pudgypenguins.com/",
            "Referrer-Policy": "strict-origin-when-cross-origin"
        }
        
        response = requests.get(url, headers=headers, impersonate="chrome110", timeout=30)
        
        if response.status_code == 429:
            log_error("Rate limit hit, waiting longer...")
            time.sleep(MAX_DELAY * 2)
            return None
            
        if response.status_code != 200:
            log_error(f"API request failed with status code: {response.status_code}")
            return None
            
        return response.json()
    except Exception as e:
        log_error(f"Failed to get message: {str(e)}")
        return None

def get_auth_token(signature, signingDate, wallet_address, chain_type="evm"):
    try:
        random_delay()
        url = "https://api.clusters.xyz/v0.1/airdrops/pengu/auth/token"
        headers = {
            "accept": "*/*",
            "accept-language": "en-GB,en-US;q=0.9,en;q=0.8",
            "content-type": "application/json",
            "priority": "u=1, i",
            "sec-ch-ua": '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"macOS"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "cross-site",
            "Referer": "https://claim.pudgypenguins.com/",
            "Referrer-Policy": "strict-origin-when-cross-origin"
        }
        
        data = {
            "signature": signature,
            "signingDate": signingDate,
            "type": chain_type,
            "wallet": wallet_address.lower() if chain_type == "evm" else wallet_address
        }

        body = json.dumps(data)
        response = requests.post(url, headers=headers, data=body, impersonate="chrome110", timeout=30)
        
        if response.status_code == 429:
            log_error("Rate limit hit, waiting longer...")
            time.sleep(MAX_DELAY * 2)
            return None
            
        if response.status_code != 200:
            log_error(f"API request failed with status code: {response.status_code}")
            return None
            
        result = response.json()
        if not result.get('token'):
            return None
            
        return result
    except Exception as e:
        log_error(f"Failed to get token: {str(e)}")
        return None

def get_eligibility(token):
    try:
        random_delay()
        url = "https://api.clusters.xyz/v0.1/airdrops/pengu/eligibility"
        headers = {
            "accept": "*/*",
            "accept-language": "en-GB,en-US;q=0.9,en;q=0.8",
            "content-type": "application/json",
            "priority": "u=1, i",
            "sec-ch-ua": '"Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"macOS"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "cross-site",
            "Referer": "https://claim.pudgypenguins.com/",
            "Referrer-Policy": "strict-origin-when-cross-origin"
        }
        
        response = requests.post(url, headers=headers, json=[token], impersonate="chrome110", timeout=30)
        
        if response.status_code == 429:
            log_error("Rate limit hit, waiting longer...")
            time.sleep(MAX_DELAY * 2)
            return None
            
        if response.status_code != 200:
            log_error(f"API request failed with status code: {response.status_code}")
            return None
            
        result = response.json()
        if not isinstance(result, dict) or 'total' not in result:
            return None
            
        return result
    except Exception as e:
        log_error(f"Failed to get eligibility: {str(e)}")
        return None

def process_single_wallet(private_key, chain_type="evm"):
    try:
        # 1. Get message
        message_response = get_auth_message()
        if not message_response or 'message' not in message_response:
            log_error("Failed to get auth message")
            return
        
        # 2. Sign message
        message = message_response['message']
        signing_date = message_response['signingDate']
        
        if chain_type == "evm":
            signature, address = sign_message_evm(private_key, message)
        else:
            signature, address = sign_message_solana(private_key, message)
        
        log_info(f"Processing {chain_type.upper()} wallet: {address}")
        log_info(f"Signature: {signature[:20]}...")
        
        # 3. Get token
        token_response = get_auth_token(signature, signing_date, address, chain_type)
        if not token_response or 'token' not in token_response:
            log_error(f"Failed to get auth token for {address}")
            return
        
        # 4. Get eligibility information
        eligibility = get_eligibility(token_response['token'])
        if eligibility:
            total = eligibility['total']
            unclaimed = eligibility['totalUnclaimed']
            if total > 0:
                log_success(f"Found airdrop! {chain_type.upper()} {address}: {total} tokens ({unclaimed} unclaimed)")
            else:
                log_info(f"No airdrop for {chain_type.upper()} {address}")
            append_to_result(address, total, unclaimed, chain_type.upper())
            
    except Exception as e:
        log_error(f"Error processing wallet: {str(e)}")
    finally:
        with print_lock:
            print("-" * 50)

def check_solana_dependencies():
    try:
        from solders.keypair import Keypair
        return True
    except ImportError:
        log_error("Solana dependencies not found. Please install them with:")
        log_error("pip install solders")
        return False

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Process EVM and/or Solana wallets')
    parser.add_argument('--evm', action='store_true', help='Process only EVM wallets')
    parser.add_argument('--solana', action='store_true', help='Process only Solana wallets')
    args = parser.parse_args()
    
    # If no flags are specified, process both
    process_all = not args.evm and not args.solana
    process_evm = args.evm or process_all
    process_solana = args.solana or process_all
    
    evm_keys = []
    solana_keys = []
    
    # Process EVM wallets if requested
    if process_evm and os.path.exists('private_keys.txt'):
        with open('private_keys.txt', 'r') as f:
            evm_keys = [line.strip() for line in f if line.strip()]
        log_info(f"Found {len(evm_keys)} EVM wallets")
        
    # Process Solana wallets if requested
    if process_solana:
        solana_enabled = check_solana_dependencies()
        if os.path.exists('private_keys_solana.txt') and solana_enabled:
            with open('private_keys_solana.txt', 'r') as f:
                solana_keys = [line.strip() for line in f if line.strip()]
            log_info(f"Found {len(solana_keys)} Solana wallets")
        else:
            if not solana_enabled:
                log_error("Skipping Solana wallets due to missing dependencies")
    
    total_wallets = len(evm_keys) + len(solana_keys)
    if total_wallets == 0:
        if process_evm and process_solana:
            log_error("No wallet private keys found. Please create private_keys.txt and/or private_keys_solana.txt")
        elif process_evm:
            log_error("No EVM wallet private keys found. Please create private_keys.txt")
        else:
            log_error("No Solana wallet private keys found. Please create private_keys_solana.txt")
        return
        
    log_info(f"Processing {total_wallets} wallets using {THREAD_COUNT} threads")
    
    # Process wallets with thread pool
    with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        if evm_keys and process_evm:
            log_info("\nProcessing EVM wallets...")
            # Submit EVM wallets
            evm_futures = [executor.submit(process_single_wallet, key, "evm") for key in evm_keys]
            # Wait for EVM to complete
            for future in evm_futures:
                future.result()
            
        if solana_keys and process_solana:
            log_info("\nProcessing Solana wallets...")
            # Submit Solana wallets
            solana_futures = [executor.submit(process_single_wallet, key, "solana") for key in solana_keys]
            # Wait for Solana to complete
            for future in solana_futures:
                future.result()
            
    log_info("\nAll wallets processed. Check results.txt for details.")

if __name__ == "__main__":
    main()