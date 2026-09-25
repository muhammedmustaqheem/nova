"""
ReconAI Threat Intelligence & IOC Extractor
Extracts structured actionable indicators of compromise (IOCs) from recovered file streams:
- Cryptocurrency Wallets (Bitcoin, Ethereum/EVM)
- Cloud & API Credentials (AWS, Database URLs, Stripe, JWT)
- Network Host IOCs (IPv4, Domains, Ports)
"""

import re
from typing import Dict, Any, List

ETH_PATTERN = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
BTC_PATTERN = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
AWS_KEY_PATTERN = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
AWS_SECRET_PATTERN = re.compile(r"(?:AWS_SECRET_ACCESS_KEY|secret_key)\s*=\s*([a-zA-Z0-9/+=]{40})", re.IGNORECASE)
DB_URL_PATTERN = re.compile(r"(?:postgres|postgresql|mysql|mongodb|redis)://[^\s'\"<>]+", re.IGNORECASE)
STRIPE_KEY_PATTERN = re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")
JWT_PATTERN = re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b")
IPV4_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")

def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    """Extracts unique structured IOCs and credentials from a text block."""
    if not text:
        return {
            "crypto_wallets": [],
            "cloud_credentials": [],
            "database_urls": [],
            "network_ips": [],
            "api_tokens": []
        }

    crypto_wallets = list(set(ETH_PATTERN.findall(text) + BTC_PATTERN.findall(text)))
    aws_keys = list(set(AWS_KEY_PATTERN.findall(text)))
    db_urls = list(set(DB_URL_PATTERN.findall(text)))
    stripe_keys = list(set(STRIPE_KEY_PATTERN.findall(text)))
    jwts = list(set(JWT_PATTERN.findall(text)))
    
    # Filter out common local non-routable dummy IPs like 0.0.0.0 or 255.255.255.255
    raw_ips = set(IPV4_PATTERN.findall(text))
    valid_ips = [ip for ip in raw_ips if not ip.startswith("0.") and not ip.startswith("255.") and ip != "127.0.0.1"]

    credentials = aws_keys + stripe_keys
    return {
        "crypto_wallets": sorted(crypto_wallets),
        "cloud_credentials": sorted(credentials),
        "database_urls": sorted(db_urls),
        "network_ips": sorted(valid_ips),
        "api_tokens": sorted(jwts)
    }

def aggregate_case_iocs(recovered_items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregates all extracted IOCs across all recovered evidence artifacts."""
    all_wallets = set()
    all_creds = set()
    all_dbs = set()
    all_ips = set()
    all_tokens = set()
    ioc_records = []

    for item in recovered_items:
        preview = item.get("content_preview", "")
        iocs = extract_iocs_from_text(preview)
        item["extracted_iocs"] = iocs
        
        for w in iocs["crypto_wallets"]:
            all_wallets.add((w, item["filename"], "Crypto Wallet"))
            ioc_records.append({"IOC": w, "Type": "Crypto Wallet", "Source_File": item["filename"], "Category": item["category"]})
        for c in iocs["cloud_credentials"]:
            all_creds.add((c, item["filename"], "Cloud Credential"))
            ioc_records.append({"IOC": c, "Type": "Cloud Secret", "Source_File": item["filename"], "Category": item["category"]})
        for db in iocs["database_urls"]:
            all_dbs.add((db, item["filename"], "Database URL"))
            ioc_records.append({"IOC": db, "Type": "Database URL", "Source_File": item["filename"], "Category": item["category"]})
        for ip in iocs["network_ips"]:
            all_ips.add((ip, item["filename"], "Network IP"))
            ioc_records.append({"IOC": ip, "Type": "Network Host IP", "Source_File": item["filename"], "Category": item["category"]})

    return {
        "total_iocs_found": len(ioc_records),
        "records": ioc_records,
        "summary": {
            "wallets_count": len(all_wallets),
            "credentials_count": len(all_creds),
            "database_urls_count": len(all_dbs),
            "network_ips_count": len(all_ips)
        }
    }
