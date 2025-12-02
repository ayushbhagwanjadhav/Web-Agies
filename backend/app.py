from flask import Flask, request, jsonify
from flask_cors import CORS
import tldextract
import requests
import whois
import ssl
import socket
import re
import logging
import json
import yaml
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from urllib3 import PoolManager
from urllib3.exceptions import SSLError
from whois.parser import PywhoisError
import cryptography.x509
from cryptography.hazmat.backends import default_backend
from jellyfish import levenshtein_distance as lev
import time

# Trusted domains that should never be blocked
TRUSTED_DOMAINS = {
    'google.com', 'youtube.com', 'github.com', 'stackoverflow.com', 'wikipedia.org',
    'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com', 'twitter.com',
    'instagram.com', 'linkedin.com', 'reddit.com', 'netflix.com', 'spotify.com'
}

def is_trusted_domain(domain):
    """Check if domain is in trusted list"""
    return any(trusted in domain for trusted in TRUSTED_DOMAINS)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('phishguard.log'),
        logging.StreamHandler()
    ]
)
# Load configuration
with open('config.yaml') as f:
    config = yaml.safe_load(f)

# Suppress noisy library logs
logging.getLogger('urllib3').setLevel(logging.CRITICAL)

app = Flask(__name__)
CORS(app)
executor = ThreadPoolExecutor(max_workers=8)

# Load brand database
with open('brands.json') as f:
    brand_db = json.load(f)
    brand_keywords = sum(brand_db.values(), [])

EV_OIDS = [
    cryptography.x509.ObjectIdentifier("2.23.140.1.1"),
    cryptography.x509.ObjectIdentifier("1.3.6.1.4.1.34697.2.1"),
    cryptography.x509.ObjectIdentifier("1.3.6.1.4.1.17326.10.14.2.1.2"),
]

class TLSAdapter(requests.adapters.HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.set_ciphers('DEFAULT@SECLEVEL=1')
        self.poolmanager = PoolManager(
            ssl_context=ctx,
            num_pools=connections,
            maxsize=maxsize,
            block=block
        )

def is_typosquatting(domain):
    """Enhanced brand detection with substring matching"""
    # Split domain into meaningful parts
    domain_parts = re.split(r'[\d\-_]+', domain)  # Split on numbers/dashes
    
    # Check each part against brands
    for part in domain_parts:
        if len(part) < 3:  # Ignore short fragments
            continue
        for brand in brand_keywords:
            if brand in part.lower():
                return True
            if lev(part.lower(), brand) <= 2:
                return True
    
    # Check regex patterns
    patterns = [
        fr'\b({"|".join(brand_keywords)})[aeiou]{{0,2}}(s|z)?\d*[-_]?(\b|$)',
        r'(.)\1{3}',  # Quadruple character repetition
        r'[-_]{2,}',  # Multiple consecutive special chars
        r'\d+[a-z]+\d+',  # Number-letter sandwiches
        r'(web3|defi|nft|crypto)[-_]',  # Crypto-related keywords
        r'(login|verify|account|secure|wallet|auth|exchange)[-.]',  # Auth keywords
        r'[a-z]{8,}\d{3,}',  # Long strings with numbers
        r'(app|service|platform)-?v\d+'  # Versioning patterns
    ]
    return any(re.search(p, domain, re.IGNORECASE) for p in patterns)

def check_ssl(url):
    """Verify SSL/TLS connection validity"""
    try:
        if not url.startswith('https://'):
            return {'valid': True, 'error_type': None}

        session = requests.Session()
        session.mount('https://', TLSAdapter())
        response = session.get(
            url,
            timeout=8,
            headers={'User-Agent': config['user_agent']},
            allow_redirects=True,
            stream=False
        )
        return {'valid': True, 'error_type': None}
    except Exception as e:
        return {'valid': False, 'error_type': str(e)}

def get_certificate_info(domain):
    """Retrieve SSL certificate details"""
    try:
        context = ssl.create_default_context()
        context.timeout = 5
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = cryptography.x509.load_der_x509_certificate(cert_bin, default_backend())
                
                # Extract organization name
                org = None
                try:
                    org = cert.subject.get_attributes_for_oid(
                        cryptography.x509.NameOID.ORGANIZATION_NAME
                    )[0].value
                except IndexError:
                    pass
                
                # Check Extended Validation
                is_ev = False
                try:
                    ext = cert.extensions.get_extension_for_class(
                        cryptography.x509.CertificatePolicies
                    ).value
                    is_ev = any(policy.policy_identifier in EV_OIDS for policy in ext)
                except cryptography.x509.ExtensionNotFound:
                    pass
                
                return {'organization': org, 'is_ev': is_ev}
    except (socket.timeout, ConnectionRefusedError, ssl.SSLError) as e:
        return {'organization': None, 'is_ev': False}
    except Exception as e:
        logging.warning(f"Certificate error: {str(e)}")
        return {'organization': None, 'is_ev': False}

def check_domain_age(domain):
    """Check domain registration details with robust error handling"""
    max_retries = 2
    for attempt in range(max_retries):
        try:
            # Remove the timeout parameter that's causing the error
            info = whois.whois(domain)
            
            if not info or not info.domain_name:
                return {'age': None, 'exists': False}
                
            created = info.creation_date
            if not created:
                return {'age': None, 'exists': True}
                
            if isinstance(created, list):
                created = created[0]
                
            if not isinstance(created, datetime):
                return {'age': None, 'exists': True}
                
            age_days = (datetime.now() - created).days
            return {
                'age': age_days,
                'exists': True
            }
            
        except (PywhoisError, socket.timeout, ConnectionResetError) as e:
            logging.debug(f"Domain check attempt {attempt + 1} failed: {str(e)}")
            if attempt == max_retries - 1:  # Last attempt
                return {'age': None, 'exists': None}
            time.sleep(1)  # Wait before retry
            
        except Exception as e:
            logging.warning(f"Unexpected domain check error: {str(e)}")
            return {'age': None, 'exists': None}
    
    return {'age': None, 'exists': None}

def check_domain_age_fallback(domain):
    """Fallback WHOIS using public API"""
    try:
        response = requests.get(
            f"https://www.whois.com/whois/{domain}",
            timeout=5,
            headers={'User-Agent': config['user_agent']}
        )
        # Parse the response for creation date (simplified)
        if "Creation Date" in response.text:
            return {'age': None, 'exists': True}
        elif "No match for" in response.text:
            return {'age': None, 'exists': False}
        else:
            return {'age': None, 'exists': None}
    except:
        return {'age': None, 'exists': None}

def check_safe_browsing(url):
    """Check Google Safe Browsing API"""
    try:
        if not config.get('google_api_key'):
            logging.warning("No Google API key configured")
            return False
            
        response = requests.post(
            "https://safebrowsing.googleapis.com/v4/threatMatches:find",
            params={"key": config['google_api_key']},
            json={
                "client": {"clientId": "phishguard", "clientVersion": "2.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "threatEntries": [{"url": url}]
                }
            },
            timeout=8
        )
        
        if response.status_code != 200:
            logging.error(f"Safe Browsing API error: {response.status_code} - {response.text}")
            return False
            
        return bool(response.json().get('matches'))
    except Exception as e:
        logging.error(f"Safe Browsing check failed: {str(e)}")
        return False

def analyze_url(url):
    try:
        # Extract just the domain for analysis, ignore query parameters
        parsed = tldextract.extract(url)
        domain_to_analyze = f"{parsed.domain}.{parsed.suffix}"
        
        # Skip analysis for trusted domains
        if is_trusted_domain(domain_to_analyze):
            return {
                "risk_score": 0,
                "flags": ["Trusted domain"],
                "analyzed_url": url,
                "timestamp": datetime.now().isoformat()
            }
        
        # For display, keep the original URL but analyze only the domain
        display_url = url
        analysis_target = f" `https://{domain_to_analyze}` "  # Analyze the clean domain
         
        risk_score = 0
        flags = []
         
        # Bypass analysis for trusted domains
        if is_trusted_domain(domain_to_analyze):
            return {"risk_score": 0, "flags": ["Trusted Domain"], "analyzed_url": display_url, "timestamp": datetime.now().isoformat()}

        if not re.match(r'^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', url):
            return {"risk_score": 100, "flags": ["Invalid URL format"], "analyzed_url": url, "timestamp": datetime.now().isoformat()}
 
        with ThreadPoolExecutor(max_workers=4) as executor:
            # DNS resolution check on the domain only
            try:
                socket.gethostbyname(domain_to_analyze)
                dns_resolved = True
            except socket.gaierror:
                dns_resolved = False
                flags.append("DNS Resolution Failed")
                risk_score += 25
 
            if not dns_resolved:
                if is_typosquatting(domain_to_analyze): 
                    flags.append("Typosquatting Patterns Detected")
                    risk_score += 55
                return {"risk_score": min(100, risk_score), "flags": [f for f in flags if f], "analyzed_url": display_url, "timestamp": datetime.now().isoformat()}
             
            # Typosquatting check on domain only
            if is_typosquatting(domain_to_analyze): 
                flags.append("Typosquatting Patterns Detected")
                risk_score += 55
             
            # Domain age and Safe Browsing checks
            domain_future = executor.submit(check_domain_age, domain_to_analyze)
            google_future = executor.submit(check_safe_browsing, analysis_target)  # Use clean domain for Safe Browsing
             
            try:
                domain_data = domain_future.result(timeout=8)
                if domain_data['exists'] is False: 
                    flags.append("Unregistered Domain")
                    risk_score += 45
                elif domain_data['age'] is not None:
                    if domain_data['age'] < 7: 
                        flags.append("Very New Domain (<7 days)")
                        risk_score += 35
                    elif domain_data['age'] < 90: 
                        flags.append("New Domain (<90 days)")
                        risk_score += 25
            except Exception as e:
                logging.debug(f"Domain check timeout/error: {str(e)}")
             
            # Number pattern check on domain only
            if re.search(r'\d{3,}[a-z-]+\d{3,}', domain_to_analyze): 
                flags.append("Suspicious Number Pattern")
                risk_score += 40
             
            try:
                safe_browsing_match = google_future.result(timeout=8)
                if safe_browsing_match: 
                    risk_score = 100
                    flags.append("Known Phishing Site")
            except Exception as e:
                logging.debug(f"Safe Browsing check timeout: {str(e)}")
             
            # SSL checks on domain only
            if dns_resolved and risk_score < 80:
                try:
                    ssl_future = executor.submit(check_ssl, analysis_target)  # Use clean domain for SSL check
                    cert_future = executor.submit(get_certificate_info, domain_to_analyze)
                    ssl_result = ssl_future.result(timeout=5)
                    if not ssl_result['valid']: 
                        risk_score += 30
                        flags.append(f"SSL Error: {ssl_result['error_type']}")
                    cert_info = cert_future.result(timeout=6)
                    if not cert_info['is_ev'] and not cert_info['organization']: 
                        risk_score += 20
                        flags.append("Untrusted Certificate")
                except Exception as e:
                    logging.debug(f"SSL check timeout/error: {str(e)}")
         
        final_score = min(100, risk_score)
        if final_score >= config['risk_threshold']: 
            flags.append("High Risk Phishing Suspected")
         
        return {"risk_score": final_score, "flags": [f for f in flags if f], "analyzed_url": display_url, "timestamp": datetime.now().isoformat()}
     
    except Exception as e:
        logging.error(f"Analysis error for URL {url}: {str(e)}", exc_info=True)
        return {"risk_score": 100, "flags": ["Security verification failed"], "analyzed_url": url, "timestamp": datetime.now().isoformat()}

@app.route('/check', methods=['POST'])
def check_url():
    """Main API endpoint"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({"error": "Invalid request"}), 400
            
        if not isinstance(data['url'], str) or len(data['url']) > 2048:
            return jsonify({"error": "Invalid URL format"}), 400
            
        return jsonify(analyze_url(data['url']))
        
    except Exception as e:
        logging.error(f"Endpoint error: {str(e)}")
        return jsonify({"error": "Server processing error"}), 500

if __name__ == '__main__':
    app.run(
        host=config['host'],
        port=config['port'],
        threaded=True,
        debug=config['debug']
    )
