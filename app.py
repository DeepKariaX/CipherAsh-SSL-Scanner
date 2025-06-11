from flask import Flask, request, render_template, jsonify
from datetime import datetime
from typing import List
import re
import warnings
import os
import json
from cryptography.utils import CryptographyDeprecationWarning

# Suppress the specific cryptography deprecation warning for negative serial numbers
warnings.filterwarnings(
    "ignore", 
    message="Parsed a negative serial number, which is disallowed by RFC 5280"
)

from sslyze import (
    Scanner,
    ServerScanRequest,
    ServerNetworkLocation,
    ScanCommandAttemptStatusEnum,
    ServerScanStatusEnum,
    ServerScanResult,
    ScanCommand
)
from sslyze.errors import ServerHostnameCouldNotBeResolved
from sslyze.scanner.scan_command_attempt import ScanCommandAttempt

app = Flask(__name__)

# Create scanned_domains folder if it doesn't exist
SCANNED_DOMAINS_FOLDER = 'scanned_domains'
if not os.path.exists(SCANNED_DOMAINS_FOLDER):
    os.makedirs(SCANNED_DOMAINS_FOLDER)

def _print_failed_scan_command_attempt(scan_command_attempt: ScanCommandAttempt) -> str:
    return (
        f"Error when running {scan_command_attempt.scan_command}: {scan_command_attempt.error_reason}:\n"
        f"{scan_command_attempt.error_trace}"
    )

def extract_hostname(url: str) -> str:
    # Regular expression to extract hostname
    pattern = re.compile(r"https?://(www\.)?")
    hostname = pattern.sub('', url).strip().strip('/')
    return hostname

def sanitize_filename(domain: str) -> str:
    """Sanitize domain name for use as filename"""
    # Remove protocol prefixes
    sanitized = domain.replace('https://', '').replace('http://', '')
    
    # Remove trailing slashes
    sanitized = sanitized.replace('/', '_')
    
    # Replace invalid characters with underscores
    sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f\x80-\x9f]', '_', sanitized)
    
    # Replace multiple consecutive underscores with single underscore
    sanitized = re.sub(r'_+', '_', sanitized)
    
    # Remove leading/trailing underscores and dots
    sanitized = sanitized.strip('._')
    
    # Truncate to reasonable length
    if len(sanitized) > 100:
        sanitized = sanitized[:100]
    
    return sanitized or 'unknown_domain'

def get_scan_file_path(domain: str) -> str:
    """Get the file path for storing scan results"""
    filename = f"{sanitize_filename(domain)}.json"
    return os.path.join(SCANNED_DOMAINS_FOLDER, filename)

def load_existing_scan(domain: str) -> dict:
    """Load existing scan results if they exist"""
    file_path = get_scan_file_path(domain)
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error loading existing scan for {domain}: {e}")
    return None

def save_scan_results(domain: str, scan_data: dict) -> bool:
    """Save scan results to JSON file"""
    file_path = get_scan_file_path(domain)
    
    # Add metadata to scan data
    enhanced_data = {
        'domain': domain,
        'scan_timestamp': datetime.now().isoformat(),
        'scan_data': scan_data,
        'scan_history': []
    }
    
    # Load existing data if available
    existing_data = load_existing_scan(domain)
    if existing_data:
        # Preserve scan history
        enhanced_data['scan_history'] = existing_data.get('scan_history', [])
        
        # Add previous scan to history
        if 'scan_data' in existing_data and 'scan_timestamp' in existing_data:
            historical_entry = {
                'timestamp': existing_data['scan_timestamp'],
                'data': existing_data['scan_data']
            }
            enhanced_data['scan_history'].append(historical_entry)
        
        # Keep only last 10 scans in history
        enhanced_data['scan_history'] = enhanced_data['scan_history'][-10:]
    
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(enhanced_data, f, indent=2, ensure_ascii=False)
        return True
    except IOError as e:
        print(f"Error saving scan results for {domain}: {e}")
        return False

def get_all_scanned_domains() -> List[dict]:
    """Get list of all previously scanned domains with metadata"""
    domains = []
    if not os.path.exists(SCANNED_DOMAINS_FOLDER):
        return domains
    
    for filename in os.listdir(SCANNED_DOMAINS_FOLDER):
        if filename.endswith('.json'):
            file_path = os.path.join(SCANNED_DOMAINS_FOLDER, filename)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    domains.append({
                        'domain': data.get('domain', filename[:-5]),
                        'last_scan': data.get('scan_timestamp'),
                        'scan_count': len(data.get('scan_history', [])) + 1,
                        'filename': filename
                    })
            except (json.JSONDecodeError, IOError):
                continue
    
    # Sort by last scan timestamp
    domains.sort(key=lambda x: x['last_scan'], reverse=True)
    return domains

def run_ssl_scan(domain: str) -> List[ServerScanResult]:
    try:
        scan_request = ServerScanRequest(
            server_location=ServerNetworkLocation(hostname=domain),
            scan_commands={
                # Existing cipher suite scans
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.CERTIFICATE_INFO,
                
                # Additional security checks
                ScanCommand.SESSION_RESUMPTION,
                ScanCommand.SESSION_RENEGOTIATION,
                ScanCommand.HEARTBLEED,
                ScanCommand.OPENSSL_CCS_INJECTION,
                ScanCommand.TLS_COMPRESSION,
                ScanCommand.TLS_1_3_EARLY_DATA,
                ScanCommand.ELLIPTIC_CURVES,
                ScanCommand.ROBOT,
                ScanCommand.TLS_FALLBACK_SCSV,
                ScanCommand.HTTP_HEADERS
            }
        )
    except ServerHostnameCouldNotBeResolved:
        return None

    scanner = Scanner()
    scanner.queue_scans([scan_request])
    all_server_scan_results = []
    for server_scan_result in scanner.get_results():
        all_server_scan_results.append(server_scan_result)
    return all_server_scan_results

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scanned-domains', methods=['GET'])
def get_scanned_domains():
    """API endpoint to get list of all scanned domains"""
    domains = get_all_scanned_domains()
    return jsonify(domains)

@app.route('/api/scan-history/<domain>', methods=['GET'])
def get_scan_history(domain):
    """API endpoint to get scan history for a specific domain"""
    existing_data = load_existing_scan(domain)
    if existing_data:
        return jsonify({
            'domain': domain,
            'current_scan': {
                'timestamp': existing_data['scan_timestamp'],
                'data': existing_data['scan_data']
            },
            'history': existing_data.get('scan_history', [])
        })
    else:
        return jsonify({'error': 'Domain not found'}), 404

@app.route('/scan', methods=['POST'])
def scan():
    domain = request.json['domain']
    original_domain = domain  # Keep original for file naming
    domain = extract_hostname(domain)

    # Check if domain was previously scanned
    existing_scan = load_existing_scan(domain)
    is_update = existing_scan is not None

    scan_results = run_ssl_scan(domain)

    if not scan_results:
        return jsonify({"error": "Error resolving the supplied hostname or connecting to the server."}), 400

    results = []
    for server_scan_result in scan_results:
        result = {"hostname": server_scan_result.server_location.hostname}

        if server_scan_result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            result["error"] = f"Could not connect: {server_scan_result.connectivity_error_trace}"
        else:
            # Initialize all result categories
            result["ssl_2_0"] = []
            result["ssl_3_0"] = []
            result["tls_1_0"] = []
            result["tls_1_1"] = []
            result["tls_1_2"] = []
            result["tls_1_3"] = []
            result["certificates"] = []
            result["vulnerabilities"] = {}
            result["security_features"] = {}
            result["performance_features"] = {}

            # Existing cipher suite scans
            ssl2_attempt = server_scan_result.scan_result.ssl_2_0_cipher_suites
            if ssl2_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                result["ssl_2_0"].append(_print_failed_scan_command_attempt(ssl2_attempt))
            elif ssl2_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                ssl2_result = ssl2_attempt.result
                result["ssl_2_0"] = [suite.cipher_suite.name for suite in ssl2_result.accepted_cipher_suites]

            ssl3_attempt = server_scan_result.scan_result.ssl_3_0_cipher_suites
            if ssl3_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                result["ssl_3_0"].append(_print_failed_scan_command_attempt(ssl3_attempt))
            elif ssl3_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                ssl3_result = ssl3_attempt.result
                result["ssl_3_0"] = [suite.cipher_suite.name for suite in ssl3_result.accepted_cipher_suites]

            tls1_0_attempt = server_scan_result.scan_result.tls_1_0_cipher_suites
            if tls1_0_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                result["tls_1_0"].append(_print_failed_scan_command_attempt(tls1_0_attempt))
            elif tls1_0_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                tls1_0_result = tls1_0_attempt.result
                result["tls_1_0"] = [suite.cipher_suite.name for suite in tls1_0_result.accepted_cipher_suites]

            tls1_1_attempt = server_scan_result.scan_result.tls_1_1_cipher_suites
            if tls1_1_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                result["tls_1_1"].append(_print_failed_scan_command_attempt(tls1_1_attempt))
            elif tls1_1_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                tls1_1_result = tls1_1_attempt.result
                result["tls_1_1"] = [suite.cipher_suite.name for suite in tls1_1_result.accepted_cipher_suites]

            tls1_2_attempt = server_scan_result.scan_result.tls_1_2_cipher_suites
            if tls1_2_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                result["tls_1_2"].append(_print_failed_scan_command_attempt(tls1_2_attempt))
            elif tls1_2_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                tls1_2_result = tls1_2_attempt.result
                result["tls_1_2"] = [suite.cipher_suite.name for suite in tls1_2_result.accepted_cipher_suites]

            tls1_3_attempt = server_scan_result.scan_result.tls_1_3_cipher_suites
            if tls1_3_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                result["tls_1_3"].append(_print_failed_scan_command_attempt(tls1_3_attempt))
            elif tls1_3_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                tls1_3_result = tls1_3_attempt.result
                result["tls_1_3"] = [suite.cipher_suite.name for suite in tls1_3_result.accepted_cipher_suites]

            # Certificate information
            certinfo_attempt = server_scan_result.scan_result.certificate_info
            if certinfo_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                result["certificates"].append(_print_failed_scan_command_attempt(certinfo_attempt))
            elif certinfo_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                certinfo_result = certinfo_attempt.result
                for cert_deployment in certinfo_result.certificate_deployments:
                    leaf_cert = cert_deployment.received_certificate_chain[0]
                    result["certificates"].append({
                        "subject": leaf_cert.subject.rfc4514_string(),
                        "serial_number": str(leaf_cert.serial_number),
                        "public_key_type": leaf_cert.public_key().__class__.__name__,
                        "not_valid_before": leaf_cert.not_valid_before_utc.isoformat(),
                        "not_valid_after": leaf_cert.not_valid_after_utc.isoformat()
                    })

            # Vulnerability Checks
            # Heartbleed
            heartbleed_attempt = server_scan_result.scan_result.heartbleed
            if heartbleed_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                heartbleed_result = heartbleed_attempt.result
                result["vulnerabilities"]["heartbleed"] = {
                    "vulnerable": heartbleed_result.is_vulnerable_to_heartbleed,
                    "status": "VULNERABLE" if heartbleed_result.is_vulnerable_to_heartbleed else "NOT_VULNERABLE"
                }

            # OpenSSL CCS Injection
            ccs_attempt = server_scan_result.scan_result.openssl_ccs_injection
            if ccs_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                ccs_result = ccs_attempt.result
                result["vulnerabilities"]["openssl_ccs_injection"] = {
                    "vulnerable": ccs_result.is_vulnerable_to_ccs_injection,
                    "status": "VULNERABLE" if ccs_result.is_vulnerable_to_ccs_injection else "NOT_VULNERABLE"
                }

            # ROBOT
            robot_attempt = server_scan_result.scan_result.robot
            if robot_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                robot_result = robot_attempt.result
                result["vulnerabilities"]["robot"] = {
                    "vulnerable": robot_result.robot_result != "NOT_VULNERABLE_NO_ORACLE",
                    "status": robot_result.robot_result,
                    "description": f"ROBOT vulnerability status: {robot_result.robot_result}"
                }
            elif robot_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                result["vulnerabilities"]["robot"] = {
                    "vulnerable": False,
                    "status": "ERROR",
                    "description": _print_failed_scan_command_attempt(robot_attempt)
                }

            # TLS Compression (CRIME)
            compression_attempt = server_scan_result.scan_result.tls_compression
            if compression_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                compression_result = compression_attempt.result
                result["vulnerabilities"]["crime_compression"] = {
                    "vulnerable": compression_result.supports_compression,
                    "status": "VULNERABLE" if compression_result.supports_compression else "NOT_VULNERABLE"
                }

            # Session Renegotiation
            reneg_attempt = server_scan_result.scan_result.session_renegotiation
            if reneg_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                reneg_result = reneg_attempt.result
                try:
                    client_renegotiation_vulnerable = getattr(reneg_result, 'is_client_renegotiation_supported', 
                                                             getattr(reneg_result, 'accepts_client_renegotiation', False))
                    secure_renegotiation_supported = getattr(reneg_result, 'is_secure_renegotiation_supported',
                                                            getattr(reneg_result, 'supports_secure_renegotiation', False))
                    
                    result["vulnerabilities"]["session_renegotiation"] = {
                        "client_initiated_vulnerable": client_renegotiation_vulnerable,
                        "secure_renegotiation": secure_renegotiation_supported,
                        "status": "VULNERABLE" if client_renegotiation_vulnerable else "SECURE"
                    }
                except AttributeError as e:
                    result["vulnerabilities"]["session_renegotiation"] = {
                        "client_initiated_vulnerable": False,
                        "secure_renegotiation": False,
                        "status": "ERROR",
                        "description": f"Session renegotiation check failed: {str(e)}"
                    }
            elif reneg_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                result["vulnerabilities"]["session_renegotiation"] = {
                    "client_initiated_vulnerable": False,
                    "secure_renegotiation": False,
                    "status": "ERROR",
                    "description": _print_failed_scan_command_attempt(reneg_attempt)
                }

            # Security Features
            # TLS Fallback SCSV
            fallback_attempt = server_scan_result.scan_result.tls_fallback_scsv
            if fallback_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                fallback_result = fallback_attempt.result
                result["security_features"]["fallback_scsv"] = {
                    "supported": fallback_result.supports_fallback_scsv,
                    "status": "SUPPORTED" if fallback_result.supports_fallback_scsv else "NOT_SUPPORTED"
                }

            # HTTP Security Headers
            headers_attempt = server_scan_result.scan_result.http_headers
            if headers_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                headers_result = headers_attempt.result
                result["security_features"]["http_headers"] = {
                    "hsts": headers_result.strict_transport_security_header is not None,
                    "hsts_header": str(headers_result.strict_transport_security_header) if headers_result.strict_transport_security_header else None,
                    "hpkp": False,
                    "hpkp_header": None,
                    "http_request_sent": getattr(headers_result, 'http_request_sent', None),
                    "redirected_to": getattr(headers_result, 'http_path_redirected_to', None)
                }
            elif headers_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                result["security_features"]["http_headers"] = {
                    "hsts": False,
                    "hsts_header": None,
                    "hpkp": False,
                    "hpkp_header": None,
                    "error": _print_failed_scan_command_attempt(headers_attempt)
                }

            # Elliptic Curves
            curves_attempt = server_scan_result.scan_result.elliptic_curves
            if curves_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                curves_result = curves_attempt.result
                try:
                    supported_curves = getattr(curves_result, 'supported_curves', [])
                    if supported_curves:
                        result["security_features"]["elliptic_curves"] = [
                            getattr(curve, 'name', str(curve)) for curve in supported_curves
                        ]
                    else:
                        result["security_features"]["elliptic_curves"] = []
                except (AttributeError, TypeError):
                    result["security_features"]["elliptic_curves"] = []
            elif curves_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                result["security_features"]["elliptic_curves"] = []

            # Performance Features
            # Session Resumption
            resumption_attempt = server_scan_result.scan_result.session_resumption
            if resumption_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                resumption_result = resumption_attempt.result
                try:
                    session_id_resumption = getattr(resumption_result, 'session_id_resumption_result', None)
                    tls_ticket_resumption = getattr(resumption_result, 'tls_ticket_resumption_result', None)
                    
                    session_id_status = getattr(session_id_resumption, 'name', str(session_id_resumption)) if session_id_resumption else "UNKNOWN"
                    tls_ticket_status = getattr(tls_ticket_resumption, 'name', str(tls_ticket_resumption)) if tls_ticket_resumption else "UNKNOWN"
                    
                    result["performance_features"]["session_resumption"] = {
                        "session_id_resumption": session_id_status,
                        "tls_ticket_resumption": tls_ticket_status,
                        "session_id_attempts": getattr(resumption_result, 'session_id_attempted_resumptions_count', 0),
                        "session_id_successful": getattr(resumption_result, 'session_id_successful_resumptions_count', 0),
                        "tls_ticket_attempts": getattr(resumption_result, 'tls_ticket_attempted_resumptions_count', 0),
                        "tls_ticket_successful": getattr(resumption_result, 'tls_ticket_successful_resumptions_count', 0)
                    }
                except (AttributeError, TypeError) as e:
                    result["performance_features"]["session_resumption"] = {
                        "session_id_resumption": "ERROR",
                        "tls_ticket_resumption": "ERROR",
                        "session_id_attempts": 0,
                        "session_id_successful": 0,
                        "tls_ticket_attempts": 0,
                        "tls_ticket_successful": 0,
                        "error": str(e)
                    }
            elif resumption_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                result["performance_features"]["session_resumption"] = {
                    "session_id_resumption": "ERROR",
                    "tls_ticket_resumption": "ERROR",
                    "session_id_attempts": 0,
                    "session_id_successful": 0,
                    "tls_ticket_attempts": 0,
                    "tls_ticket_successful": 0,
                    "error": _print_failed_scan_command_attempt(resumption_attempt)
                }

            # TLS 1.3 Early Data
            early_data_attempt = server_scan_result.scan_result.tls_1_3_early_data
            if early_data_attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
                early_data_result = early_data_attempt.result
                try:
                    supports_early_data = getattr(early_data_result, 'supports_early_data', False)
                    result["performance_features"]["tls_1_3_early_data"] = {
                        "supported": supports_early_data,
                        "status": "SUPPORTED" if supports_early_data else "NOT_SUPPORTED"
                    }
                except (AttributeError, TypeError):
                    result["performance_features"]["tls_1_3_early_data"] = {
                        "supported": False,
                        "status": "UNKNOWN"
                    }
            elif early_data_attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                result["performance_features"]["tls_1_3_early_data"] = {
                    "supported": False,
                    "status": "ERROR",
                    "error": _print_failed_scan_command_attempt(early_data_attempt)
                }

        results.append(result)

    # Save scan results to JSON file
    if results and not results[0].get("error"):
        save_success = save_scan_results(domain, results[0])
        if save_success:
            print(f"{'Updated' if is_update else 'Saved'} scan results for {domain}")
        else:
            print(f"Failed to save scan results for {domain}")

    return jsonify(results)

if __name__ == "__main__":
    app.run(debug=True)
