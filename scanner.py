# The goal of this project is to create a network scanner that will find vulnerabilities, 
# compare them to related CVE's and explain how we can remediate them

# Import nmap and tools
import nmap
import requests
from fpdf import FPDF



# create function for scanning targets
def scan_target(targets):
    nm = nmap.PortScanner()
    nm.scan(hosts=targets,arguments='-sV --version-all')

    results = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port, data in nm[host][proto].items():
                results.append({
                    'host': host,
                    'protocol': proto,
                    'port': port,
                    'service': data.get('name'),
                    'product': data.get('product'),
                    'version': data.get('version'),
                    'cpe': data.get('cpe' , '')
                })  
    return results





def normalize_cpe(cpe):
    if cpe.startswith('cpe:/'):
        parts = cpe.split(':')
        if len(parts) >= 4:
            vendor = parts[2]
            product = parts[3]
            return f'cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*'
    return cpe

def check_vuln(cpe, product=None):
    vulns = []

    try:
        def parse_vulns(data):
            results = []
            for item in data.get('vulnerabilities', []):
                cve_id = item['cve']['id']
                description = item['cve']['descriptions'][0]['value']

                # Publication date
                pub_date = item['cve'].get('published', 'Unknown')
                year = pub_date.split('-')[0] if pub_date != 'Unknown' else 'Unknown'

                # Skip anything before 2015
                if year != 'Unknown' and int(year) < 2015:
                    continue

                # Severity (CVSS v3 preferred)
                severity = 'Unknown'
                metrics = item['cve'].get('metrics', {})
                if 'cvssMetricV31' in metrics:
                    severity = metrics['cvssMetricV31'][0]['cvssData']['baseSeverity']
                elif 'cvssMetricV30' in metrics:
                    severity = metrics['cvssMetricV30'][0]['cvssData']['baseSeverity']
                elif 'cvssMetricV2' in metrics:
                    severity = metrics['cvssMetricV2'][0]['baseSeverity']

                results.append((cve_id, description, severity, year))
            return results

        # Try CPE first
        if cpe and cpe.startswith('cpe:2.3'):
            url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}'
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                vulns.extend(parse_vulns(response.json()))

        # Fallback to keyword search
        if not vulns and product:
            url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={product}'
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                vulns.extend(parse_vulns(response.json()))

            # Broader keyword fallback
            if not vulns:
                keyword = product.split()[0]
                url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}'
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    vulns.extend(parse_vulns(response.json()))

    except Exception as e:
        print(f'Error fetching vulnerabilities: {e}')

    return vulns







targ = '128.85.32.179'
findings = scan_target(targ)


REMEDIATION_GUIDANCE = {
    22: [
        "Use key-based authentication instead of passwords",
        "Disable root login over SSH",
        "Keep OpenSSH updated to the latest version"
    ],
    80: [
        "Apply latest patches to your web server (Apache, Nginx, IIS)",
        "Use HTTPS instead of plain HTTP",
        "Run web application vulnerability scans regularly"
    ],
    443: [
        "Ensure TLS certificates are valid and up to date",
        "Disable weak ciphers and protocols (SSLv2/3, TLS 1.0/1.1)",
        "Enable HSTS (HTTP Strict Transport Security)"
    ],
    135: [
        "Restrict RPC access to trusted internal networks",
        "Apply Microsoft security updates regularly",
        "Monitor for unusual RPC traffic"
    ],
    139: [
        "Disable SMBv1 (deprecated and insecure)",
        "Restrict NetBIOS/SMB access to internal networks",
        "Apply Microsoft patches promptly"
    ],
    445: [
        "Disable SMBv1 and enforce SMBv3",
        "Restrict SMB access to trusted IP ranges",
        "Apply Microsoft security updates regularly"
    ],
    3389: [
        "Apply latest Microsoft patches (e.g. BlueKeep CVE-2019-0708)",
        "Restrict RDP access via firewall/NSG rules",
        "Enable Network Level Authentication (NLA)",
        "Consider VPN or bastion host instead of exposing RDP directly"
    ],
    53: [
        "Upgrade DNS server software to latest version",
        "Enable DNSSEC validation",
        "Restrict recursion to trusted clients"
    ]
}

def export_to_pdf(findings, filename='vulnerability_report.pdf'):
    pdf = FPDF()
    pdf.add_page()

    # Big bold heading
    pdf.set_font('Arial', 'B', 20)   # Bigger font size, bold
    pdf.cell(200, 15, 'Vulnerability Scan Report', ln=True, align='C')
    pdf.ln(10)

    for f in findings:
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(200, 10, f'Host: {f["host"]}', ln=True)
        pdf.set_font('Arial', size=11)
        pdf.cell(200, 10, f'Port: {f["port"]} / Protocol: {f["protocol"]}', ln=True)
        pdf.cell(200, 10, f'Service: {f["service"]} / Product: {f["product"]}', ln=True)
        pdf.cell(200, 10, f'CPE: {f["cpe"]}', ln=True)

        vulns = check_vuln(f['cpe'], f['product'])
        if vulns:
            # Vulnerabilities in red
            pdf.set_text_color(255, 0, 0)   # Red text
            pdf.cell(200, 10, 'Vulnerabilities:', ln=True)
            for v in vulns[:5]:
                cve_id, description, severity, year = v
                pdf.multi_cell(0, 10, f'- {cve_id}: {description}')
                pdf.multi_cell(0, 10, f'  Severity: {severity} | Published: {year}')
            pdf.set_text_color(0, 0, 0)     # Reset back to black
        else:
            pdf.set_text_color(0, 128, 0)   # Green for "None found"
            pdf.cell(200, 10, 'Vulnerabilities: None found.', ln=True)
            pdf.set_text_color(0, 0, 0)     # Reset back to black

        if f['port'] in REMEDIATION_GUIDANCE:
            pdf.set_font('Arial', 'B', 11)
            pdf.cell(200, 10, 'Remediation Recommendations:', ln=True)
            pdf.set_font('Arial', size=11)
            for rec in REMEDIATION_GUIDANCE[f['port']]:
                pdf.multi_cell(0, 10, f'  - {rec}')

        pdf.ln(5)
        pdf.cell(200, 10, '-'*80, ln=True)
        pdf.ln(5)
    pdf.output(filename)
    
export_to_pdf(findings)
print('Report saved as vulnerability_report.pdf')








