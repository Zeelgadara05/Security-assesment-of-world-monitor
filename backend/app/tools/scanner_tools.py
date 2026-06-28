import subprocess
import shlex
import re
import random
import time
import logging

logger = logging.getLogger("cyberagent.tools")

def sanitize_input(target: str) -> str:
    """Sanitize the target input to prevent command injection."""
    # Only allow domain characters, numbers, dashes, dots, slashes, and spaces
    sanitized = re.sub(r"[^a-zA-Z0-9.\-/]", "", target)
    return sanitized

def run_subfinder(target: str, simulation: bool = True) -> dict:
    """Runs subfinder subdomain discovery."""
    sanitized = sanitize_input(target)
    logger.info(f"Running subfinder for target: {sanitized}")
    if simulation:
        time.sleep(2)
        domains = [f"api.{sanitized}", f"dev.{sanitized}", f"vpn.{sanitized}", f"staging.{sanitized}", f"db.{sanitized}"]
        return {
            "tool": "subfinder",
            "status": "success",
            "subdomains": domains,
            "log": f"[subfinder] Discovered {len(domains)} subdomains for {sanitized}\n" + "\n".join([f"  -> {d}" for d in domains])
        }

    try:
        cmd = ["subfinder", "-d", sanitized, "-silent"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return {"tool": "subfinder", "status": "success", "subdomains": subdomains, "log": result.stdout}
    except Exception as e:
        logger.error(f"Error running subfinder: {e}")
        return {"tool": "subfinder", "status": "failed", "error": str(e), "log": f"Error running subfinder: {e}"}

def run_assetfinder(target: str, simulation: bool = True) -> dict:
    """Runs assetfinder subdomain discovery."""
    sanitized = sanitize_input(target)
    logger.info(f"Running assetfinder for target: {sanitized}")
    if simulation:
        time.sleep(1.5)
        domains = [f"admin.{sanitized}", f"test.{sanitized}", f"portal.{sanitized}"]
        return {
            "tool": "assetfinder",
            "status": "success",
            "subdomains": domains,
            "log": f"[assetfinder] Discovered {len(domains)} subdomains for {sanitized}\n" + "\n".join([f"  -> {d}" for d in domains])
        }

    try:
        cmd = ["assetfinder", "--subs-only", sanitized]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return {"tool": "assetfinder", "status": "success", "subdomains": subdomains, "log": result.stdout}
    except Exception as e:
        logger.error(f"Error running assetfinder: {e}")
        return {"tool": "assetfinder", "status": "failed", "error": str(e), "log": f"Error running assetfinder: {e}"}

def run_dnsx(target: str, subdomains: list, simulation: bool = True) -> dict:
    """Runs dnsx for resolving active subdomains and checking DNS records."""
    logger.info(f"Running dnsx for {len(subdomains)} subdomains of target: {target}")
    if simulation:
        time.sleep(2)
        resolved = []
        for sub in subdomains:
            resolved.append({
                "subdomain": sub,
                "ip": f"104.244.{random.randint(10, 250)}.{random.randint(10, 250)}",
                "type": "A"
            })
        return {
            "tool": "dnsx",
            "status": "success",
            "resolved": resolved,
            "log": "[dnsx] DNS resolution complete.\n" + "\n".join([f"  -> {r['subdomain']} resolves to {r['ip']}" for r in resolved])
        }

    try:
        resolved = []
        for sub in subdomains:
            sanitized_sub = sanitize_input(sub)
            cmd = ["dnsx", "-d", sanitized_sub, "-resp-only", "-silent"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            ips = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            for ip in ips:
                resolved.append({"subdomain": sub, "ip": ip, "type": "A"})
        return {"tool": "dnsx", "status": "success", "resolved": resolved, "log": f"[dnsx] Resolved {len(resolved)} targets successfully."}
    except Exception as e:
        logger.error(f"Error running dnsx: {e}")
        return {"tool": "dnsx", "status": "failed", "error": str(e), "log": f"Error running dnsx: {e}"}

def run_nmap(target: str, simulation: bool = True) -> dict:
    """Runs nmap for open ports & service discovery."""
    sanitized = sanitize_input(target)
    logger.info(f"Running nmap port scan on: {sanitized}")
    if simulation:
        time.sleep(3)
        ports = [
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "product": "nginx", "version": "1.18.0"},
            {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "product": "nginx", "version": "1.18.0"},
            {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH", "version": "8.2p1"},
            {"port": 8080, "protocol": "tcp", "state": "open", "service": "http-proxy", "product": "Node.js Express", "version": "4.17.1"},
            {"port": 5432, "protocol": "tcp", "state": "filtered", "service": "postgresql", "product": "PostgreSQL", "version": "14.0"}
        ]
        log = f"Starting Nmap 7.92 ( https://nmap.org ) at 2026-06-28 13:54\n"
        log += f"Nmap scan report for {sanitized}\n"
        log += f"Host is up (0.015s latency).\n"
        log += f"PORT     STATE    SERVICE       VERSION\n"
        for p in ports:
            log += f"{p['port']}/{p['protocol']:4} {p['state']:8} {p['service']:13} {p['product']} {p['version']}\n"
        return {"tool": "nmap", "status": "success", "ports": ports, "log": log}

    try:
        cmd = ["nmap", "-sV", "-T4", "-F", sanitized]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        # Parse standard nmap format simply
        ports = []
        for line in result.stdout.splitlines():
            match = re.match(r"^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)\s*(.*)$", line)
            if match:
                ports.append({
                    "port": int(match.group(1)),
                    "protocol": match.group(2),
                    "state": match.group(3),
                    "service": match.group(4),
                    "product": match.group(5) or "unknown",
                    "version": ""
                })
        return {"tool": "nmap", "status": "success", "ports": ports, "log": result.stdout}
    except Exception as e:
        logger.error(f"Error running nmap: {e}")
        return {"tool": "nmap", "status": "failed", "error": str(e), "log": f"Error running nmap: {e}"}

def run_httpx(target: str, simulation: bool = True) -> dict:
    """Runs httpx to probe web endpoints and active status."""
    sanitized = sanitize_input(target)
    logger.info(f"Running httpx web discovery on: {sanitized}")
    if simulation:
        time.sleep(2)
        urls = [f"https://{sanitized}", f"http://{sanitized}"]
        return {
            "tool": "httpx",
            "status": "success",
            "urls": [{"url": u, "status_code": 200, "title": "Dashboard", "server": "nginx"} for u in urls],
            "log": "\n".join([f"{u} [200] [nginx] [Dashboard]" for u in urls])
        }

    try:
        cmd = ["httpx", "-u", sanitized, "-status-code", "-title", "-web-server", "-silent"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        urls = []
        for line in result.stdout.splitlines():
            # Parses standard httpx format
            parts = line.strip().split(" ")
            if len(parts) >= 2:
                urls.append({
                    "url": parts[0],
                    "status_code": int(parts[1].strip("[]")),
                    "title": parts[2] if len(parts) > 2 else "",
                    "server": parts[3] if len(parts) > 3 else "unknown"
                })
        return {"tool": "httpx", "status": "success", "urls": urls, "log": result.stdout}
    except Exception as e:
        logger.error(f"Error running httpx: {e}")
        return {"tool": "httpx", "status": "failed", "error": str(e), "log": f"Error running httpx: {e}"}

def run_nuclei(target: str, simulation: bool = True) -> dict:
    """Runs nuclei vulnerability scanning."""
    sanitized = sanitize_input(target)
    logger.info(f"Running nuclei scans on: {sanitized}")
    if simulation:
        time.sleep(4)
        vulnerabilities = [
            {
                "title": "SQL Injection in Admin Search Parameter",
                "severity": "Critical",
                "cve": "CVE-2024-3849",
                "cvss": 9.8,
                "owasp": "A03:2021-Injection",
                "mitre": "T1190 - Exploit Public-Facing Application",
                "description": "A SQL injection vulnerability exists in the admin search page due to improper sanitation of user inputs.",
                "remediation": "Use parameterized queries and bind variables in all database search APIs.",
                "proof_of_concept": f"GET /admin/search?q=1'+OR+'1'='1' HTTP/1.1\nHost: {sanitized}\n\nResponse:\nHTTP/1.1 200 OK\n[Contains complete user table data]"
            },
            {
                "title": "Missing Content-Security-Policy (CSP) Header",
                "severity": "Low",
                "cve": None,
                "cvss": 3.1,
                "owasp": "A05:2021-Security Misconfiguration",
                "mitre": "T1566 - Phishing / XSS Delivery",
                "description": "Content-Security-Policy header is missing on the client side login shell.",
                "remediation": "Add Content-Security-Policy HTTP response headers to control loaded source scripts.",
                "proof_of_concept": f"GET /login HTTP/1.1\nHost: {sanitized}\n\nResponse Headers:\nHTTP/1.1 200 OK\nServer: nginx\n(No Content-Security-Policy header present)"
            },
            {
                "title": "Outdated jQuery Version (1.12.4) with Vulnerability",
                "severity": "Medium",
                "cve": "CVE-2015-9251",
                "cvss": 6.1,
                "owasp": "A06:2021-Vulnerable and Outdated Components",
                "mitre": "T1203 - Exploitation for Client Execution",
                "description": "The client application uses jQuery 1.12.4, which is susceptible to cross-site scripting attacks via remote links.",
                "remediation": "Upgrade jQuery dependency to the latest supported version (3.7.1 or higher).",
                "proof_of_concept": f"Detected in resource bundle: /js/jquery-1.12.4.min.js"
            }
        ]
        log = "[nuclei] Scan started against " + sanitized + "\n"
        for v in vulnerabilities:
            log += f"[{v['severity']}] [{v['cve'] or 'unknown'}] [{v['owasp']}] -> {v['title']}\n"
        return {"tool": "nuclei", "status": "success", "vulnerabilities": vulnerabilities, "log": log}

    try:
        cmd = ["nuclei", "-target", sanitized, "-severity", "info,low,medium,high,critical", "-silent"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        # Parse nuclei json or custom output lines
        vulnerabilities = []
        for line in result.stdout.splitlines():
            if line.strip():
                # Raw text format parses
                vulnerabilities.append({
                    "title": line,
                    "severity": "Medium",
                    "cve": "CVE-Unknown",
                    "cvss": 5.0,
                    "owasp": "A05:2021-Security Misconfiguration",
                    "mitre": "T1190",
                    "description": line,
                    "remediation": "Apply standard security updates and restrict endpoint controls.",
                    "proof_of_concept": f"Output line: {line}"
                })
        return {"tool": "nuclei", "status": "success", "vulnerabilities": vulnerabilities, "log": result.stdout}
    except Exception as e:
        logger.error(f"Error running nuclei: {e}")
        return {"tool": "nuclei", "status": "failed", "error": str(e), "log": f"Error running nuclei: {e}"}

def run_gau(target: str, simulation: bool = True) -> dict:
    """Runs gau (GetAllUrls) to fetch cached web endpoints."""
    sanitized = sanitize_input(target)
    logger.info(f"Running gau web crawlers on: {sanitized}")
    if simulation:
        time.sleep(1.5)
        urls = [
            f"https://{sanitized}/login",
            f"https://{sanitized}/admin",
            f"https://{sanitized}/api/v1/users",
            f"https://{sanitized}/dashboard",
            f"https://{sanitized}/settings"
        ]
        return {
            "tool": "gau",
            "status": "success",
            "urls": urls,
            "log": f"[gau] Discovered {len(urls)} cached endpoints:\n" + "\n".join([f"  - {u}" for u in urls])
        }

    try:
        cmd = ["gau", sanitized]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        urls = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return {"tool": "gau", "status": "success", "urls": urls, "log": result.stdout}
    except Exception as e:
        logger.error(f"Error running gau: {e}")
        return {"tool": "gau", "status": "failed", "error": str(e), "log": f"Error running gau: {e}"}

def run_whatweb(target: str, simulation: bool = True) -> dict:
    """Runs whatweb to discover server technologies and frameworks."""
    sanitized = sanitize_input(target)
    logger.info(f"Running whatweb profile on: {sanitized}")
    if simulation:
        time.sleep(1.5)
        techs = ["React 19", "FastAPI", "Python 3.12", "PostgreSQL", "Nginx 1.18.0", "Ubuntu"]
        return {
            "tool": "whatweb",
            "status": "success",
            "techs": techs,
            "log": f"WhatWeb scan report for {sanitized}\n" + f"Summary: nginx[1.18.0], React[19], FastAPI[Python 3.12], Ubuntu Linux"
        }

    try:
        cmd = ["whatweb", sanitized]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return {"tool": "whatweb", "status": "success", "techs": [result.stdout.strip()], "log": result.stdout}
    except Exception as e:
        logger.error(f"Error running whatweb: {e}")
        return {"tool": "whatweb", "status": "failed", "error": str(e), "log": f"Error running whatweb: {e}"}
