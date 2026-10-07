#!/usr/bin/env python
import json
import hashlib
import os
import requests
import re
import geoip2.database
from datetime import datetime
from collections import Counter
import configparser
from typing import Tuple, List, Dict, Any
import colorama
from colorama import Fore, Style
import pyfiglet
import subprocess
import sys

import subprocess
import sys

def check_and_install_dependencies(requirements_file="requirements.txt"):
   
    try:
        with open(requirements_file, "r") as file:
            dependencies = file.read().splitlines()

        missing_dependencies = []

        for dependency in dependencies:
            package_name = dependency.split("==")[0]  # Nome del pacchetto
            required_version = dependency.split("==")[1] if "==" in dependency else None
            
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "show", package_name],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                )
                if result.returncode != 0:  # Il pacchetto non è installato
                    raise ValueError("Package not found")

                if required_version:
                    for line in result.stdout.splitlines():
                        if line.startswith("Version:"):
                            installed_version = line.split(":")[1].strip()
                            if installed_version != required_version:
                                raise ValueError("Version mismatch")
            except ValueError:
                missing_dependencies.append(dependency)

        if missing_dependencies:
            print(f"Missing or outdated dependencies found: {', '.join(missing_dependencies)}")
            print("Installing/upgrading dependencies...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", *missing_dependencies])
            print("All missing or outdated dependencies have been installed/upgraded.")
        else:
            print("All dependencies are already installed and up-to-date.")

    except FileNotFoundError:
        print(f"Error: The file '{requirements_file}' was not found.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")



# Check if the 'config.ini' file exists in the current directory
if not os.path.isfile('config.ini'):
    print("'config.ini' file not found!")
    os.system('python3 config.py')


colorama.init(autoreset=True)

# --- CONFIGURATION MANAGEMENT ---
LOG_HASH_FILE = 'log_hash.txt' 



class ConfigManager:
    """Manages configuration loading and validation."""
    
    def __init__(self, config_file: str):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)
        self.required_keys = [
            ('DEFAULT', 'geoip_db'),
            ('DEFAULT', 'max_requests_per_minute'),
            ('DEFAULT', 'risky_country'),
            ('DEFAULT', 'unusual_status_codes'),
            ('DEFAULT', 'log_file'),
            ('API', 'abuseipdb_api_key'),
            ('WHITELIST', 'ips'),
            ('SCORING', 'path_risk_weight'),
            ('SCORING', 'geo_risk_weight'),
            ('SCORING', 'abuse_ip_weight'),
            ('SCORING', 'request_volume_weight')
        ]
        self._validate_config()
    
    def _validate_config(self):
        for section, key in self.required_keys:
            if not self.config.has_option(section, key):
                raise KeyError(f"Missing {key} in section [{section}] of config.ini")
    
    def get(self, section: str, key: str) -> str:
        return self.config[section][key]

    def get_list(self, section: str, key: str) -> List[str]:
            """Restituisce una lista di valori separati da virgola dal file di configurazione."""
            value = self.config[section][key]
            return [item.strip() for item in value.split(',')]

        

# --- ASCII Art Banner ---
def print_banner():
    banner = pyfiglet.figlet_format("RequestShield")
    print(Fore.CYAN + Style.BRIGHT + banner)
    print(Fore.LIGHTCYAN_EX + "Your comprehensive log analysis tool for enhanced request monitoring.\n")

# --- RISK SCORE CALCULATION ---

class RiskScoreCalculator:
    def __init__(self, config: ConfigManager):
        self.config = config
        self.path_risk_weight = float(config.get('SCORING', 'path_risk_weight'))
        self.geo_risk_weight = float(config.get('SCORING', 'geo_risk_weight'))
        self.abuse_ip_weight = float(config.get('SCORING', 'abuse_ip_weight'))
        self.request_volume_weight = float(config.get('SCORING', 'request_volume_weight'))
        self.risky_countries = config.get_list('DEFAULT', 'risky_country')  # Ottieni la lista dei paesi a rischio

    def calculate_score(self, ip_data: Dict[str, Any]) -> Tuple[float, List[str]]:
        anomalies = []  # Deve essere una lista
        
        # Verifica del paese dell'IP
        geo_risk_score = 10 if ip_data.get('geo_country') in self.risky_countries else 0
        if geo_risk_score:
            anomalies.append("Unexpected Country")  # Aggiungi una stringa alla lista

        abuse_ip_score = ip_data.get('abuse_score', 0)
        if abuse_ip_score > 0:
            anomalies.append("IP Abuse Detected")  # Aggiungi una stringa alla lista

        path_risk_score = 10 if ip_data.get('suspicious_path') else 0
        if path_risk_score:
            anomalies.append("Suspicious Path")  # Aggiungi una stringa alla lista

        request_volume_score = 5 if ip_data.get('request_count') > int(self.config.get('DEFAULT', 'max_requests_per_minute')) else 0
        if request_volume_score:
            anomalies.append("High Request Volume")  # Aggiungi una stringa alla lista

        total_score = (
            path_risk_score * self.path_risk_weight +
            geo_risk_score * self.geo_risk_weight +
            abuse_ip_score * self.abuse_ip_weight +
            request_volume_score * self.request_volume_weight
        )
        return min(100, total_score), anomalies  # anomalies deve essere una lista di stringhe


# --- GEOLOCATION & ABUSE CHECK ---

class GeoLocationChecker:
    """Checks geolocation of IP addresses."""
    
    def __init__(self, geo_db_path: str):
        self.reader = geoip2.database.Reader(geo_db_path)
    
    def get_country(self, ip: str) -> str:
        try:
            response = self.reader.country(ip)
            return response.country.name
        except Exception:
            return "Unknown"
class AbuseIPChecker:
    """Checks IP against AbuseIPDB."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
    
    def check_ip(self, ip: str) -> Tuple[bool, int]:
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }
        try:
            response = requests.get(url, headers=headers, params={'ipAddress': ip, 'maxAgeInDays': '90'}, timeout=5)
            response.raise_for_status()  # Raises HTTPError for bad responses
            data = response.json().get('data', {})
            
            # Restituisci i risultati dell'API
            is_public = data.get('isPublic', False)
            abuse_score = data.get('abuseConfidenceScore', 0)
            return is_public, abuse_score

        except requests.RequestException as e:
            print(Fore.RED + f"API request failed for IP {ip}: {e}")
            return False, 0


# --- TRAFFIC ANALYSIS ---

class TrafficAnalyzer:
    """Analyzes traffic and identifies anomalies."""
    
    def __init__(self, config: ConfigManager, geo_checker: GeoLocationChecker, abuse_checker: AbuseIPChecker, risk_calculator: RiskScoreCalculator):
        self.config = config
        self.geo_checker = geo_checker
        self.abuse_checker = abuse_checker
        self.risk_calculator = risk_calculator
        self.traffic_stats = {
            'total_requests': 0,
            'total_bytes': 0,
            'unique_ips': set(),
            'ip_requests': {},
            'suspicious_requests': []
        }

    def parse_log_line(self, log_line: str):
        """
        Parse both standard Apache/Nginx Combined Log Format and the
        original RequestShield custom format.
        """
        log_line = log_line.strip()
        if not log_line:
            return

        # Standard Combined Log Format:
        # IP - - [date] "METHOD PATH HTTP/VERSION" STATUS SIZE "REFERER" "USER_AGENT"
        combined_pattern = re.compile(
            r'^(?P<ip>\S+)\s+'
            r'(?P<identity>\S+)\s+'
            r'(?P<user>\S+)\s+'
            r'\[(?P<datetime>[^\]]+)\]\s+'
            r'"(?P<method>\S+)\s+(?P<path>\S+)\s+[^"]+"\s+'
            r'(?P<status>\d{3})\s+'
            r'(?P<size>\d+)\s+'
            r'"(?P<referer>[^"]*)"\s+'
            r'"(?P<user_agent>[^"]*)"\s*$'
        )

        # Original RequestShield custom format:
        custom_pattern = re.compile(
            r'^(?P<ip>\S+)\s+(?P<domain>\S+)\s+\S+\s+'
            r'\[(?P<datetime>[^\]]+)\]\s+'
            r'"(?P<method>\S+)\s+(?P<path>\S+)\s+[^"]+"\s+'
            r'(?P<status>\d{3})\s+(?P<size>\d+)\s+'
            r'"[^"]*"\s+"(?P<user_agent>[^"]*)"\s+'
            r'\|\s*(?P<tls>\S+)\s*\|\s*'
            r'(?P<req_time>\S+)\s+(?P<resp_time>\S+)\s+'
            r'(?P<cache_hit>\S+)\s+(?P<cache_status>\S+)\s+'
            r'(?P<other>.+)$'
        )

        match = combined_pattern.match(log_line)
        if not match:
            match = custom_pattern.match(log_line)

        if not match:
            return

        ip = match.group('ip')
        path = match.group('path')
        status = int(match.group('status'))
        size = int(match.group('size'))

        # Flag admin/login paths, including paths below those endpoints.
        is_suspicious = (
            path == '/admin'
            or path == '/login'
            or path.startswith('/admin/')
            or path.startswith('/login/')
        )

        is_abusive, abuse_score = self.abuse_checker.check_ip(ip)
        geo_country = self.geo_checker.get_country(ip)

        # Update request counts.
        self.traffic_stats['total_requests'] += 1
        self.traffic_stats['total_bytes'] += size
        self.traffic_stats['unique_ips'].add(ip)
        self.traffic_stats['ip_requests'][ip] = (
            self.traffic_stats['ip_requests'].get(ip, 0) + 1
        )

        ip_data = {
            'suspicious_path': is_suspicious,
            'geo_country': geo_country,
            'abuse_score': abuse_score,
            'request_count': self.traffic_stats['ip_requests'][ip]
        }

        risk_score, anomalies = self.risk_calculator.calculate_score(ip_data)

        if anomalies:
            self.traffic_stats['suspicious_requests'].append({
                'ip': ip,
                'risk_score': risk_score,
                'status': status,
                'path': path,
                'anomalies': ", ".join(anomalies)
            })

# --- HTML REPORT GENERATION ---

def generate_html_report(report_filename: str, traffic_stats: Dict[str, Any], get_country: callable):
    """Genera un report HTML basato sui dati di traffico."""
    current_datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    total_bytes_mb = traffic_stats['total_bytes'] / (1024 * 1024)
    avg_requests_per_ip = (traffic_stats['total_requests'] / len(traffic_stats['unique_ips'])) if traffic_stats['unique_ips'] else 0
    logo_url = "OM_Logo.png"

    # HTML content
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>RequestShield Report</title>
        <style>
            body {{
                font-family: 'Arial', sans-serif;
                background-color: #121212;
                color: #EAEAEA;
            }}
            .container {{
                width: 80%;
                margin: 50px auto;
            }}
            h1 {{
                text-align: center;
                color: #FF4500;
            }}
            h2 {{
                color: #FF5733;
                border-bottom: 2px solid #FF5733;
                padding-bottom: 10px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 20px;
            }}
            th, td {{
                padding: 12px;
                border: 1px solid #fff;
            }}
            th {{
                background-color: #FF5733;
                color: #000;
            }}
            td {{
                background-color: #1E1E1E;
            }}
            .suspicious {{
                background-color: #ff3333;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div style="text-align: center; margin-bottom: 20px;">
                <img src="{logo_url}" alt="OSINT Matter Logo" width="150" height="150">
            </div>
            <h1>RequestShield Report</h1>
            <p><strong>Report generated on:</strong> {current_datetime}</p>
            <h2>Traffic Summary</h2>
            <p>
                Total Requests: {traffic_stats['total_requests']}<br>
                Total Data (MB): {total_bytes_mb:.2f}<br>
                Unique IPs: {len(traffic_stats['unique_ips'])}<br>
                Average Requests per IP: {avg_requests_per_ip:.2f}
            </p>

            <h2>Suspicious Requests Summary</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Country</th>
                        <th>Total Requests</th>
                        <th>Requested Paths</th>
                        <th>Anomalies</th>
                        <th>Status</th>
                        <th>Risk Score</th>
                    </tr>
                </thead>
                <tbody>
    """

    # IP Aggregation fo susp requests
    suspicious_ips = {}
    for req in traffic_stats['suspicious_requests']:
        ip = req.get('ip', 'N/A')
        status = req.get('status', 'N/A')
        anomalies = req.get('anomalies', 'None')
        risk_score = req.get('risk_score', 0)
        path = req.get('path', 'N/A')
        country = get_country(ip)

        if ip not in suspicious_ips:
            suspicious_ips[ip] = {
                'total_requests': 0,
                'country': country,
                'anomalies': set(),
                'status': status,
                'risk_score': risk_score,
                'paths': set()
            }

        suspicious_ips[ip]['total_requests'] += 1
        suspicious_ips[ip]['anomalies'].update(anomalies.split(', '))  # Converti da stringa a set
        suspicious_ips[ip]['paths'].add(path)

    # Debug suspicious_ips
    print("DEBUG: suspicious_ips content:")
    for ip, details in suspicious_ips.items():
        print(f"IP: {ip}, Details: {details}")

    # Popola la tabella con i dettagli degli IP sospetti
    for ip, details in suspicious_ips.items():
        if not details:
            print(f"Warning: Missing details for IP {ip}, skipping.")
            continue

        anomalies = ', '.join(details['anomalies']) if isinstance(details['anomalies'], (list, set)) else details['anomalies']
        paths = ', '.join(details['paths']) if isinstance(details['paths'], (list, set)) else 'None'
        country = details.get('country', 'Unknown')
        total_requests = details.get('total_requests', 0)
        status = details.get('status', 'N/A')
        risk_score = details.get('risk_score', 0)

        html_content += f"""
        <tr class="suspicious">
            <td>{ip}</td>
            <td>{country}</td>
            <td>{total_requests}</td>
            <td>{paths}</td>
            <td>{anomalies}</td>
            <td>{status}</td>
            <td>{risk_score}</td>
        </tr>
        """
    
    html_content += """
                </tbody>
            </table>
        </div>
        <footer>
            <p>Report created by <a href="https://osintmatter.com" target="_blank">OSINT Matter</a></p>
        </footer>
    </body>
    </html>
    """
    with open(report_filename, 'w') as report_file:
        report_file.write(html_content)


# --- CALCULATE HASH ---

def compute_file_hash(file_path):
    """Compute the SHA256 hash of the given file."""
    hash_sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            hash_sha256.update(byte_block)
    return hash_sha256.hexdigest()

def load_last_log_hash():
    """Load the last computed hash of the log file."""

    try:
        with open(LOG_HASH_FILE, 'r') as hash_file:
            return hash_file.read().strip()
    except FileNotFoundError:
        return None

def save_current_log_hash(current_hash):
    """Save the current hash of the log file."""
    with open(LOG_HASH_FILE, 'w') as hash_file:
        hash_file.write(current_hash)

# --- MAIN EXECUTION WITH UX ENHANCEMENTS ---

def main():
    print_banner()

    check_and_install_dependencies()


    config = configparser.ConfigParser()
    config.read('config.ini')
    log_file_path = config.get('DEFAULT', 'log_file')

    current_log_hash = compute_file_hash(log_file_path)
    last_log_hash = load_last_log_hash()

    if current_log_hash == last_log_hash:
        print("No changes detected in the log file since the last run. Exiting.")
        return

    print("Analyzing log file...")  # Indicate analysis start

    config = ConfigManager('config.ini')
    geo_checker = GeoLocationChecker(config.get('DEFAULT', 'geoip_db'))
    abuse_checker = AbuseIPChecker(config.get('API', 'abuseipdb_api_key'))
    risk_calculator = RiskScoreCalculator(config)

    analyzer = TrafficAnalyzer(config, geo_checker, abuse_checker, risk_calculator)

    
    if not os.path.isfile(log_file_path) or not os.access(log_file_path, os.R_OK):
        print(Fore.RED + f"Error: The log file '{log_file_path}' does not exist or is not readable.")
        return
    
    # Count lines for progress bar
    with open(log_file_path) as f:
        total_lines = sum(1 for _ in f)

    print(Fore.YELLOW + Style.BRIGHT + "\nStarting log analysis...")

    with open(log_file_path) as log_file:
        for i, log_line in enumerate(log_file, start=1):
            analyzer.parse_log_line(log_line)
            print(Fore.LIGHTGREEN_EX + f"\rProcessing logs: [{'#' * (i * 40 // total_lines)}{'.' * (40 - (i * 40 // total_lines))}] {i}/{total_lines}", end='')

    # Summary Section
    print("\n\n" + Fore.LIGHTMAGENTA_EX + Style.BRIGHT + "Analysis Complete!")
    print(Fore.LIGHTYELLOW_EX + f"Total Requests Processed: {analyzer.traffic_stats['total_requests']}")
    print(Fore.LIGHTBLUE_EX + f"Unique IPs Analyzed: {len(analyzer.traffic_stats['unique_ips'])}")
    print(Fore.LIGHTRED_EX + f"Suspicious Requests Found: {len(analyzer.traffic_stats['suspicious_requests'])}")

    # Generate and display path to report
    report_filename = "report.html"
    generate_html_report(report_filename, analyzer.traffic_stats, geo_checker.get_country)
    save_current_log_hash(current_log_hash)  # Save only after successful processing
    print(Fore.GREEN + f"\nHTML report generated: {report_filename}\n")

if __name__ == "__main__":
    main()
