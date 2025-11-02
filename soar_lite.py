# soar_lite.py
# Reads IPs, queries AbuseIPDB and VirusTotal, outputs JSON and CSV.
from dotenv import load_dotenv
import os
import requests
import json
import csv
import time

# ---------- CONFIG ----------
load_dotenv()
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

USE_ABUSEIPDB  = True
USE_VIRUSTOTAL = True

INPUT_FILE   = "suspicious_ips.txt"
OUTPUT_JSON  = "enriched_ips.json"
OUTPUT_CSV   = "enriched_ips.csv"
PAUSE_SECONDS = 1.5

# ---------- FUNCTIONS ----------

def read_ips(path):
    ips = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ips.append(line)
    return ips

def enrich_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key":     ABUSEIPDB_API_KEY
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=15)
        if resp.status_code != 200:
            return {"error": f"status {resp.status_code}", "raw": resp.text}
        data = resp.json().get("data", {})
        return {
            "abuseConfidenceScore": data.get("abuseConfidenceScore"),
            "countryCode":           data.get("countryCode"),
            "lastReportedAt":        data.get("lastReportedAt"),
            "totalReports":          data.get("totalReports")
        }
    except Exception as e:
        return {"error": "exception", "details": str(e)}

def enrich_virustotal_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code != 200:
            return {"error": f"status {resp.status_code}", "raw": resp.text}
        obj = resp.json().get("data", {}).get("attributes", {})
        return {
            "as_owner":             obj.get("as_owner"),
            "country":              obj.get("country"),
            "last_analysis_stats":  obj.get("last_analysis_stats")
        }
    except Exception as e:
        return {"error": "exception", "details": str(e)}

def enrich_ip(ip):
    result = {"ip": ip}
    if USE_ABUSEIPDB and ABUSEIPDB_API_KEY:
        result["abuseipdb"] = enrich_abuseipdb(ip)
        time.sleep(PAUSE_SECONDS)
    if USE_VIRUSTOTAL and VIRUSTOTAL_API_KEY:
        result["virustotal"] = enrich_virustotal_ip(ip)
        time.sleep(PAUSE_SECONDS)
    return result

def save_json(data, path):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def save_csv(data, path):
    """Save results to a CSV file with clear headings and a Risk Level column."""
    fieldnames = [
        "IP Address",
        "Abuse Confidence Score",
        "Total Abuse Reports",
        "Reported Country",
        "VirusTotal Owner (ASN)",
        "VirusTotal Country",
        "Risk Level"
    ]

    with open(path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for item in data:
            abuse_score = item.get("abuseipdb", {}).get("abuseConfidenceScore") or 0
            abuse_reports = item.get("abuseipdb", {}).get("totalReports") or 0

            # Determine risk level
            if abuse_score >= 70:
                risk = "HIGH RISK"
            elif abuse_score >= 30:
                risk = "SUSPICIOUS"
            else:
                risk = "SAFE"

            writer.writerow({
                "IP Address": item.get("ip"),
                "Abuse Confidence Score": abuse_score,
                "Total Abuse Reports": abuse_reports,
                "Reported Country": item.get("abuseipdb", {}).get("countryCode"),
                "VirusTotal Owner (ASN)": item.get("virustotal", {}).get("as_owner") if item.get("virustotal") else None,
                "VirusTotal Country": item.get("virustotal", {}).get("country") if item.get("virustotal") else None,
                "Risk Level": risk
            })


def main():
    ips = read_ips(INPUT_FILE)
    print(f"Found {len(ips)} IPs to enrich.")
    results = []
    for ip in ips:
        print("Enriching", ip)
        r = enrich_ip(ip)
        results.append(r)
    print("Saving results...")
    save_json(results, OUTPUT_JSON)
    save_csv(results, OUTPUT_CSV)
    print("Done. Outputs:", OUTPUT_JSON, OUTPUT_CSV)

if __name__ == "__main__":
    main()
