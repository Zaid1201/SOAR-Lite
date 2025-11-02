# SOAR Lite Project

## Overview
This is a project that enriches IP addresses using two free APIs: AbuseIPDB and VirusTotal. It simulates a simple SOAR (Security Orchestration, Automation, and Response) workflow.

## Project Structure
- `soar_lite.py` — Main Python script.
- `suspicious_ips.txt` — File containing example IP addresses.
- `README.txt` — Instructions and setup steps.

## Requirements
1. Install Python 3 (https://www.python.org/downloads/)
2. Install requests library:
   ```bash
   python -m pip install requests
   ```
3. Get free API keys:
   - **AbuseIPDB**: https://www.abuseipdb.com/
   - **VirusTotal**: https://www.virustotal.com/

## Setup
Open .env file and add assign the API keys to their corresponding variables.

## Run the Script
1. Place your suspicious IP addresses in `suspicious_ips.txt` (one IP per line).
2. Open a terminal in the project folder.
3. Run:
   ```bash
   python soar_lite.py
   ```
4. After running, two files will appear:
   - `enriched_ips.json` — detailed results.
   - `enriched_ips.csv` — summarized results.

## Troubleshooting
- If you get a `429 Too Many Requests` error, increase `PAUSE_SECONDS` inside the script.
- If you see a `status 403` or `401`, check that your API key is correct and active.
- Make sure the IPs are public (not private ranges like 192.168.x.x).

## Notes
- Keep your API keys secret and never upload them publicly.
- If you get partial results, it means one API responded and the other didn’t — that’s okay.
