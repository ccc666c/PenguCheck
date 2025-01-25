# Pudgy Penguins Airdrop Checker

A tool to check airdrop eligibility for Pudgy Penguins across both EVM and Solana chains.

## Features

- Check airdrop eligibility for both EVM and Solana wallets
- Process multiple wallets in parallel
- Rate limiting to avoid API throttling
- Detailed output with wallet addresses and airdrop amounts
- Option to process only EVM or only Solana wallets

## Setup

1. Install required packages:
```bash
pip install eth-account curl-cffi colorama solders base58
```

2. Create input files:
- For EVM wallets: Create `private_keys.txt` with one private key per line
- For Solana wallets: Create `private_keys_solana.txt` with one private key per line

## Usage

Run all wallets:
```bash
python3 contract.py
```

Run only EVM wallets:
```bash
python3 contract.py --evm
```

Run only Solana wallets:
```bash
python3 contract.py --solana
```

## Output

Results are saved to `results.txt` in the format:
```
[CHAIN] wallet_address: Airdrop amount: X, Unclaimed amount: Y
```

## Configuration

You can adjust these parameters in `contract.py`:
- `THREAD_COUNT`: Number of concurrent threads (default: 2)
- `MIN_DELAY`: Minimum delay between requests in seconds (default: 3)
- `MAX_DELAY`: Maximum delay between requests in seconds (default: 5)

## Notes

- The script includes rate limiting and random delays to avoid API throttling
- Failed attempts are logged but don't stop the entire process
- Progress is shown in real-time with color-coded output

## Important Notes

1. Security Reminders:
   - Keep private key file secure
   - Do not share with others
   - Recommend using dedicated checking wallets

2. Running Recommendations:
   - Use a stable network connection
   - Don't set thread count too high
   - Recommend checking no more than 100 wallets at a time

3. Common Issues:
   - If "Failed to get message" appears, check network connection
   - If "Please create private_keys.txt" appears, confirm file exists and format is correct
   - If a wallet check fails, program will continue with the next one

## Error Handling

1. Network Errors:
   - Program will automatically retry
   - If failures persist, check network connection

2. Format Errors:
   - Check if private_keys.txt format is correct
   - Ensure private key format is correct (66 hexadecimal digits)

3. Other Errors:
   - Check command line error messages
   - Handle according to the prompts

## Contact

If you encounter issues or need help, feel free to contact:
- Telegram: [@ccc666333](https://t.me/ccc666333)

## Disclaimer

1. This tool is for learning and research purposes only
2. Do not use for illegal purposes
3. Users are responsible for any consequences of using this tool

---
Made with ❤️ by [@ccc666333](https://t.me/ccc666333)