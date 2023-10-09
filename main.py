import re
import subprocess
import threading
import time
import argparse

REGEX_PATTERNS = {
    "Slack Token": "(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
    "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
    "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "Amazon MWS Auth Token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "AWS AppSync GraphQL Key": "da2-[a-z0-9]{26}",
    "Facebook Access Token": "EAACEdEose0cBA[0-9A-Za-z]+",
    "Facebook OAuth": "[fF][aA][cC][eE][bB][oO][oO][kK].{0,20}['|\"][0-9a-f]{32}['|\"]",
    "GitHub": "[gG][iI][tT][hH][uU][bB].{0,20}['|\"][0-9a-zA-Z]{35,40}['|\"]",
    "Google (GCP) Service-account": "\"type\": \"service_account\"",
    "Heroku API Key": "[hH][eE][rR][oO][kK][uU].{0,20}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "Json Web Token": "eyJhbGciOiJ",
    "MailChimp API Key": "[0-9a-f]{32}-us[0-9]{1,2}",
    "Mailgun API Key": "key-[0-9a-zA-Z]{32}",
    "Password in URL": "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
    "PayPal Braintree Access Token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
    "Picatic API Key": "sk_live_[0-9a-z]{32}",
    "Slack Webhook": "https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Stripe API Key": "sk_live_[0-9a-zA-Z]{24}",
    "Stripe Restricted API Key": "rk_live_[0-9a-zA-Z]{24}",
    "Square Access Token": "sq0atp-[0-9A-Za-z\\-_]{22}",
    "Square OAuth Secret": "sq0csp-[0-9A-Za-z\\-_]{43}",
    "Telegram Bot API Key": "[0-9]+:AA[0-9A-Za-z\\-_]{33}",
    "Twilio API Key": "SK[0-9a-fA-F]{32}",
    "Github Auth Creds": "https:\/\/[a-zA-Z0-9]{40}@github\.com",
    "Generic API Key": "[aA][pP][iI]_?[kK][eE][yY].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "Generic Secret": "[sS][eE][cC][rR][eE][tT].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "AWS API Key": "((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})"
}

lock = threading.Lock()

def fetch_content_from_url(url, delay):
    time.sleep(delay)
    try:
        result = subprocess.run(["curl", "-s", url], capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError:
        return ""

def search_sensitive_data(content):
    findings = {}
    for key, pattern in REGEX_PATTERNS.items():
        matches = re.findall(pattern, content)
        if matches:
            findings[key] = matches
    return findings

def process_url(idx, total_urls, url, delay, output_file):
    print(f"\rProcessing {idx} из {total_urls}: {url}", end="")
    content = fetch_content_from_url(url, delay)
    findings = search_sensitive_data(content)
    with lock:
        if findings:
            print(f"\nSensitive data found for {url}:\n")
            for key, matches in findings.items():
                print(f"{key}: {', '.join(matches)}\n")
                with open(output_file, 'a') as f:
                    f.write(f"Sensitive data found for {url}:\n")
                    f.write(f"{key}: {', '.join(matches)}\n")
            print("------\n")

def main():
    parser = argparse.ArgumentParser(description="Searches for sensitive data on web pages")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("-d", "--delay", type=int, default=1, help="Delay between requests in seconds")
    parser.add_argument("-i", "--input", type=str, default="urls.txt", help="Source file with URL or a separate URL")
    parser.add_argument("-o", "--output", type=str, default="results.txt", help="File for recording results")
    args = parser.parse_args()

    if "http://" in args.input or "https://" in args.input:
        urls = [args.input]
    else:
        with open(args.input, "r") as file:
            urls = [line.strip() for line in file]

    total_urls = len(urls)
    threads = []

    open(args.output, 'w').close()

    for idx, url in enumerate(urls, start=1):
        t = threading.Thread(target=process_url, args=(idx, total_urls, url, args.delay, args.output))
        t.start()
        threads.append(t)

        if len(threads) >= args.threads:
            for t in threads:
                t.join()
            threads = []

    for t in threads:
        t.join()

if __name__ == "__main__":
    main()
