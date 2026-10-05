import base64
import requests

# API key goes here
import os
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


def check_url(url: str):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    response = requests.get(endpoint, headers=headers)

    # URL not found
    if response.status_code == 404:
        return {
            "success": False,
            "message": "This URL has not been scanned by VirusTotal yet."
        }

    # API error
    if response.status_code != 200:
        return {
            "success": False,
            "message": f"VirusTotal API Error ({response.status_code})"
        }

    data = response.json()["data"]["attributes"]

    stats = data["last_analysis_stats"]
    results = data["last_analysis_results"]

    malicious = stats["malicious"]
    suspicious = stats["suspicious"]
    harmless = stats["harmless"]

    total = sum(stats.values())

    flagged = malicious + suspicious

    score = max(0, 100 - (flagged * 15))

    # Decide status
    if score >= 80:
        status = "SAFE"
    elif score >= 50:
        status = "SUSPICIOUS"
    else:
        status = "DANGEROUS"

    # Store flagged vendors
    vendors = []

    for engine, res in results.items():
        if res["category"] in ["malicious", "suspicious"]:
            vendors.append({
                "engine": engine,
                "result": res["result"]
            })

    # Return all data to Flask
    return {
        "success": True,
        "url": url,
        "status": status,
        "score": score,
        "total": total,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "vendors": vendors
    }


if __name__ == "__main__":

    target = input("Enter URL: ").strip()

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    result = check_url(target)

    print(result)