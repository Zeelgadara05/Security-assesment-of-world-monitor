"""Scanner tool adapters.

Every scanner in this project is a thin, typed adapter over an external CLI
binary.  Two boundaries are strictly enforced here:

  * availability -- when a binary is not installed on PATH the adapter returns
    an explicit NOT_INSTALLED state.  The workflow NEVER fabricates a result
    for a missing scanner and never silently substitutes simulated output for
    a real failure.
  * execution    -- binaries are always invoked as a list of arguments with
    ``shell=False`` so no attacker-controlled input can be interpreted as a
    shell command.  Inputs pass through ``sanitize_input`` and each execution
    has a hard timeout.

Simulation remains a distinct, explicit mode: when ``simulation=True`` the
adapters return deterministic synthetic markers (prefixed with [SIMULATED]
upstream) and they must never be presented as real findings.
"""
import subprocess
import shutil
import re
import json
import time
import logging

logger = logging.getLogger("cyberagent.tools")

# ---------------------------------------------------------------------------
# Tool result states
# ---------------------------------------------------------------------------
STATE_COMPLETED = "Completed"
STATE_NOT_INSTALLED = "Not Installed"
STATE_EXECUTION_FAILED = "Execution Failed"
STATE_TIMEOUT = "Timeout"
STATE_PARSE_FAILED = "Parse Failed"

# Per-scanner execution budget (seconds). Chosen generously because security
# tools like nmap can legitimately take a while on large targets.
BINARY_TIMEOUT_SECONDS = 90


def sanitize_input(target: str) -> str:
    """Sanitize the target input to prevent command injection."""
    # Only allow domain characters, numbers, dashes, dots, slashes, and spaces
    sanitized = re.sub(r"[^a-zA-Z0-9.\-/]", "", target)
    return sanitized


def is_tool_installed(binary: str) -> bool:
    """True when the scanner executable is resolvable on PATH."""
    return shutil.which(binary) is not None


class ScannerAdapter:
    """Base adapter: owns availability, execution and result-state mapping."""

    tool_name: str = ""
    binary: str = ""

    def available(self) -> bool:
        return is_tool_installed(self.binary)

    def simulate(self, target: str, sanitized: str) -> dict:
        raise NotImplementedError()

    def run_real(self, target: str, sanitized: str) -> dict:
        raise NotImplementedError()

    def execute(self, args: list[str], sanitized_arg: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            check=True,
            timeout=BINARY_TIMEOUT_SECONDS,
            shell=False,
        )

    def run(self, target: str, simulation: bool = True) -> dict:
        sanitized = sanitize_input(target)
        logger.info(f"Running {self.tool_name} for target: {sanitized}")
        if simulation:
            return self.simulate(target, sanitized)
        if not self.available():
            logger.warning(f"{self.binary} is not installed on PATH; skipping {self.tool_name}.")
            return {
                "tool": self.tool_name,
                "status": STATE_NOT_INSTALLED,
                "error": f"{self.binary} not found on PATH",
                "log": f"[{self.tool_name}] NOT INSTALLED: {self.binary} is not available on PATH. No scan was executed.",
            }
        try:
            return self.run_real(target, sanitized)
        except FileNotFoundError:
            return {
                "tool": self.tool_name,
                "status": STATE_NOT_INSTALLED,
                "error": f"{self.binary} not found on PATH",
                "log": f"[{self.tool_name}] NOT INSTALLED: {self.binary} is not available on PATH. No scan was executed.",
            }
        except subprocess.TimeoutExpired:
            logger.error(f"{self.tool_name} exceeded {BINARY_TIMEOUT_SECONDS}s timeout.")
            return {
                "tool": self.tool_name,
                "status": STATE_TIMEOUT,
                "error": f"Execution exceeded {BINARY_TIMEOUT_SECONDS}s",
                "log": f"[{self.tool_name}] TIMEOUT: execution exceeded {BINARY_TIMEOUT_SECONDS}s and was terminated.",
            }
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running {self.tool_name}: {e.stderr or e}")
            return {
                "tool": self.tool_name,
                "status": STATE_EXECUTION_FAILED,
                "error": (e.stderr or str(e))[:500],
                "log": f"[{self.tool_name}] EXECUTION FAILED: {e.stderr or e}",
            }
        except Exception as e:
            logger.error(f"Error running {self.tool_name}: {e}")
            return {
                "tool": self.tool_name,
                "status": STATE_EXECUTION_FAILED,
                "error": str(e),
                "log": f"[{self.tool_name}] EXECUTION FAILED: {e}",
            }


# ---------------------------------------------------------------------------
# Per-scanner adapters
# ---------------------------------------------------------------------------
class SubfinderAdapter(ScannerAdapter):
    tool_name = "subfinder"
    binary = "subfinder"

    def simulate(self, target, sanitized):
        time.sleep(2)
        domains = [f"api.{sanitized}", f"dev.{sanitized}", f"vpn.{sanitized}", f"staging.{sanitized}", f"db.{sanitized}"]
        return {
            "tool": self.tool_name,
            "status": "success",
            "subdomains": domains,
            "log": f"[subfinder] Discovered {len(domains)} subdomains for {sanitized}\n" + "\n".join([f"  -> {d}" for d in domains]),
        }

    def run_real(self, target, sanitized):
        result = self.execute(["subfinder", "-d", sanitized, "-silent"])
        subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return {"tool": self.tool_name, "status": "success", "subdomains": subdomains, "log": result.stdout}


class AssetfinderAdapter(ScannerAdapter):
    tool_name = "assetfinder"
    binary = "assetfinder"

    def simulate(self, target, sanitized):
        time.sleep(1.5)
        domains = [f"admin.{sanitized}", f"test.{sanitized}", f"portal.{sanitized}"]
        return {
            "tool": self.tool_name,
            "status": "success",
            "subdomains": domains,
            "log": f"[assetfinder] Discovered {len(domains)} subdomains for {sanitized}\n" + "\n".join([f"  -> {d}" for d in domains]),
        }

    def run_real(self, target, sanitized):
        result = self.execute(["assetfinder", "--subs-only", sanitized])
        subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return {"tool": self.tool_name, "status": "success", "subdomains": subdomains, "log": result.stdout}


class DnsxAdapter(ScannerAdapter):
    tool_name = "dnsx"
    binary = "dnsx"

    def simulate(self, target, sanitized):
        subdomains = self._subdomains()
        time.sleep(2)
        resolved = []
        for sub in subdomains:
            resolved.append({
                "subdomain": sub,
                "ip": f"104.244.{random_int(10, 250)}.{random_int(10, 250)}",
                "type": "A",
            })
        return {
            "tool": self.tool_name,
            "status": "success",
            "resolved": resolved,
            "log": "[dnsx] DNS resolution complete.\n" + "\n".join([f"  -> {r['subdomain']} resolves to {r['ip']}" for r in resolved]),
        }

    def _subdomains(self):
        # dnsx receives subdomains gathered by subfinder/assetfinder; when the
        # workflow has none it falls back to the target itself.
        return getattr(self, "_provided_subdomains", None) or [self._last_target]

    def set_subdomains(self, subdomains: list):
        self._provided_subdomains = subdomains

    def run(self, target, simulation=True, subdomains=None):
        sanitized = sanitize_input(target)
        if subdomains is not None:
            self._provided_subdomains = subdomains
        self._last_target = sanitized
        logger.info(f"Running dnsx for {len(subdomains or [])} subdomains of target: {sanitized}")
        if simulation:
            return self.simulate(target, sanitized)
        if not self.available():
            return {
                "tool": self.tool_name,
                "status": STATE_NOT_INSTALLED,
                "error": "dnsx not found on PATH",
                "log": "[dnsx] NOT INSTALLED: dnsx is not available on PATH. No scan was executed.",
            }
        try:
            resolved = []
            for sub in (subdomains or [sanitized]):
                sanitized_sub = sanitize_input(sub)
                result = subprocess.run(
                    ["dnsx", "-d", sanitized_sub, "-resp-only", "-silent"],
                    capture_output=True, text=True, timeout=BINARY_TIMEOUT_SECONDS, shell=False,
                )
                ips = [line.strip() for line in result.stdout.splitlines() if line.strip()]
                for ip in ips:
                    resolved.append({"subdomain": sub, "ip": ip, "type": "A"})
            return {"tool": self.tool_name, "status": "success", "resolved": resolved, "log": f"[dnsx] Resolved {len(resolved)} targets successfully."}
        except subprocess.TimeoutExpired:
            return {"tool": self.tool_name, "status": STATE_TIMEOUT, "error": "timeout", "log": "[dnsx] TIMEOUT."}
        except Exception as e:
            logger.error(f"Error running dnsx: {e}")
            return {"tool": self.tool_name, "status": STATE_EXECUTION_FAILED, "error": str(e), "log": f"Error running dnsx: {e}"}

    def run_real(self, target, sanitized):
        resolved = []
        for sub in (self._provided_subdomains or [sanitized]):
            sanitized_sub = sanitize_input(sub)
            result = subprocess.run(
                ["dnsx", "-d", sanitized_sub, "-resp-only", "-silent"],
                capture_output=True, text=True, timeout=BINARY_TIMEOUT_SECONDS, shell=False,
            )
            ips = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            for ip in ips:
                resolved.append({"subdomain": sub, "ip": ip, "type": "A"})
        return {"tool": self.tool_name, "status": "success", "resolved": resolved, "log": f"[dnsx] Resolved {len(resolved)} targets successfully."}


class NmapAdapter(ScannerAdapter):
    tool_name = "nmap"
    binary = "nmap"

    def simulate(self, target, sanitized):
        time.sleep(3)
        ports = [
            {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "product": "nginx", "version": "1.18.0"},
            {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "product": "nginx", "version": "1.18.0"},
            {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH", "version": "8.2p1"},
            {"port": 8080, "protocol": "tcp", "state": "open", "service": "http-proxy", "product": "Node.js Express", "version": "4.17.1"},
            {"port": 5432, "protocol": "tcp", "state": "filtered", "service": "postgresql", "product": "PostgreSQL", "version": "14.0"},
        ]
        log = f"Starting Nmap 7.92 ( https://nmap.org ) at 2026-06-28 13:54\n"
        log += f"Nmap scan report for {sanitized}\n"
        log += f"Host is up (0.015s latency).\n"
        log += f"PORT     STATE    SERVICE       VERSION\n"
        for p in ports:
            log += f"{p['port']}/{p['protocol']:4} {p['state']:8} {p['service']:13} {p['product']} {p['version']}\n"
        return {"tool": self.tool_name, "status": "success", "ports": ports, "log": log}

    def run_real(self, target, sanitized):
        result = self.execute(["nmap", "-sV", "-T4", "-F", sanitized])
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
                    "version": "",
                })
        return {"tool": self.tool_name, "status": "success", "ports": ports, "log": result.stdout}


class HttpxAdapter(ScannerAdapter):
    tool_name = "httpx"
    binary = "httpx"

    def simulate(self, target, sanitized):
        time.sleep(2)
        urls = [f"https://{sanitized}", f"http://{sanitized}"]
        return {
            "tool": self.tool_name,
            "status": "success",
            "urls": [{"url": u, "status_code": 200, "title": "Dashboard", "server": "nginx"} for u in urls],
            "log": "\n".join([f"{u} [200] [nginx] [Dashboard]" for u in urls]),
        }

    def run_real(self, target, sanitized):
        result = self.execute(["httpx", "-u", sanitized, "-status-code", "-title", "-web-server", "-silent"])
        urls = []
        for line in result.stdout.splitlines():
            parts = line.strip().split(" ")
            if len(parts) >= 2:
                try:
                    status_code = int(parts[1].strip("[]"))
                except ValueError:
                    status_code = 0
                urls.append({
                    "url": parts[0],
                    "status_code": status_code,
                    "title": parts[2] if len(parts) > 2 else "",
                    "server": parts[3] if len(parts) > 3 else "unknown",
                })
        return {"tool": self.tool_name, "status": "success", "urls": urls, "log": result.stdout}


class GauAdapter(ScannerAdapter):
    tool_name = "gau"
    binary = "gau"

    def simulate(self, target, sanitized):
        time.sleep(1.5)
        urls = [
            f"https://{sanitized}/login",
            f"https://{sanitized}/admin",
            f"https://{sanitized}/api/v1/users",
            f"https://{sanitized}/dashboard",
            f"https://{sanitized}/settings",
        ]
        return {
            "tool": self.tool_name,
            "status": "success",
            "urls": urls,
            "log": f"[gau] Discovered {len(urls)} cached endpoints:\n" + "\n".join([f"  - {u}" for u in urls]),
        }

    def run_real(self, target, sanitized):
        result = self.execute(["gau", sanitized])
        urls = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return {"tool": self.tool_name, "status": "success", "urls": urls, "log": result.stdout}


class WhatwebAdapter(ScannerAdapter):
    tool_name = "whatweb"
    binary = "whatweb"

    def simulate(self, target, sanitized):
        time.sleep(1.5)
        techs = ["React 19", "FastAPI", "Python 3.12", "PostgreSQL", "Nginx 1.18.0", "Ubuntu"]
        return {
            "tool": self.tool_name,
            "status": "success",
            "techs": techs,
            "log": f"WhatWeb scan report for {sanitized}\n" + f"Summary: nginx[1.18.0], React[19], FastAPI[Python 3.12], Ubuntu Linux",
        }

    def run_real(self, target, sanitized):
        result = self.execute(["whatweb", sanitized])
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return {"tool": self.tool_name, "status": "success", "techs": lines or [result.stdout.strip()], "log": result.stdout}


class NucleiAdapter(ScannerAdapter):
    tool_name = "nuclei"
    binary = "nuclei"

    def simulate(self, target, sanitized):
        time.sleep(4)
        # Simulation NEVER fabricates security findings. Findings are derived
        # exclusively from real tool output normalized into persisted
        # observations; a simulated run has none, so it produces none.
        log = (
            f"[nuclei] [SIMULATION] No vulnerability findings were synthesized. "
            f"Findings require real engine output plus persisted evidence.\n"
            f"[nuclei] Scan started against {sanitized} (simulated)\n"
        )
        return {"tool": self.tool_name, "status": "success", "vulnerabilities": [], "log": log}

    def run_real(self, target, sanitized):
        # JSON output mode: every line is a self-contained finding record from
        # the engine. Output is recorded verbatim except for a lossless JSON
        # re-serialization; nothing is fabricated when the scanner is silent.
        result = self.execute(["nuclei", "-target", sanitized, "-json", "-silent"])
        vulnerabilities = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                # A malformed line means the runner's output cannot be trusted;
                # surface the raw line as a parse failure rather than inventing
                # a structured finding the engine did not produce.
                return {
                    "tool": self.tool_name,
                    "status": STATE_PARSE_FAILED,
                    "error": "Malformed nuclei JSON output line",
                    "log": "[nuclei] PARSE FAILED: got a non-JSON output line from nuclei -json. Raw line below.\n" + line,
                }
            info = record.get("info") or {}
            vulnerabilities.append({
                "title": info.get("name") or record.get("template-id") or "Nuclei finding",
                "severity": (info.get("severity") or "info").capitalize(),
                "cve": ", ".join((info.get("classification") or {}).get("cve-id") or []) or None,
                "cvss": None,
                "owasp": None,
                "mitre": None,
                "description": info.get("description") or "Nuclei-generated finding.",
                "remediation": info.get("remediation") or "Apply the relevant security patch or configuration fix.",
                "proof_of_concept": f"{record.get('matched-at', target)} {record.get('matcher-name', '')}".strip(),
                "matched_at": record.get("matched-at") or target,
                "template_id": record.get("template-id"),
                "matcher_name": record.get("matcher-name"),
            })
        return {"tool": self.tool_name, "status": "success", "vulnerabilities": vulnerabilities, "log": result.stdout}


# ---------------------------------------------------------------------------
# Registry + module-level functions kept for workflow compatibility
# ---------------------------------------------------------------------------
ADAPTERS = {
    "subfinder": SubfinderAdapter(),
    "assetfinder": AssetfinderAdapter(),
    "dnsx": DnsxAdapter(),
    "nmap": NmapAdapter(),
    "httpx": HttpxAdapter(),
    "gau": GauAdapter(),
    "whatweb": WhatwebAdapter(),
    "nuclei": NucleiAdapter(),
}


def run_subfinder(target: str, simulation: bool = True) -> dict:
    return ADAPTERS["subfinder"].run(target, simulation)


def run_assetfinder(target: str, simulation: bool = True) -> dict:
    return ADAPTERS["assetfinder"].run(target, simulation)


def run_dnsx(target: str, subdomains: list, simulation: bool = True) -> dict:
    return ADAPTERS["dnsx"].run(target, simulation, subdomains=subdomains)


def run_nmap(target: str, simulation: bool = True) -> dict:
    return ADAPTERS["nmap"].run(target, simulation)


def run_httpx(target: str, simulation: bool = True) -> dict:
    return ADAPTERS["httpx"].run(target, simulation)


def run_nuclei(target: str, simulation: bool = True) -> dict:
    return ADAPTERS["nuclei"].run(target, simulation)


def run_gau(target: str, simulation: bool = True) -> dict:
    return ADAPTERS["gau"].run(target, simulation)


def run_whatweb(target: str, simulation: bool = True) -> dict:
    return ADAPTERS["whatweb"].run(target, simulation)


def random_int(lo: int, hi: int) -> int:
    import random
    return random.randint(lo, hi)