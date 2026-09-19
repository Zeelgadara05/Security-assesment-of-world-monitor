"""Real, stdlib-only reconnaissance and service-scanning probes.

Phase 3 replaces fabricated security intelligence with genuine observations.
Unlike the external CLIs (which this environment may not have installed), these
probes always perform a real action and always return real results:

  * ``dns_probe``  -- resolver query via ``socket.getaddrinfo``,
  * ``tcp_probe``  -- TCP connect handshake against a port list,
  * ``http_probe`` -- real HTTP(S) GET capturing status, headers, title, body.

Each probe returns a normalized report: ``observations`` is the ordered list of
factual, evidence-carrying observations the workflow persists verbatim.  A probe
that genuinely failed is recorded as a ``*_error``/``*_empty`` observation --
"nothing was found" and "nothing could be measured" are both honest, evidenced
outcomes, never silently dropped and never fabricated into a finding.

These probes are the ONLY path into the findings engine.  External scanner
output may only contribute facts once it has been normalized into an
observation (e.g. parsed nuclei -json records become ``nuclei_finding``
observations).
"""
import re
import socket
import ssl
import urllib.error
import urllib.request

# Curated, passive-only probe set. Small so a full real-mode scan stays quiet.
TCP_PORT_PROBE_LIST = [22, 80, 443, 3000, 3306, 5432, 8080, 8443]

_DNS_TIMEOUT_SECONDS = 5
_TCP_CONNECT_TIMEOUT_SECONDS = 2
_HTTP_TIMEOUT_SECONDS = 8
_HTTP_BODY_LIMIT = 20000
_RAW_LIMIT = 4000

_TITLE_RE = re.compile(r"<title[^>]*>\s*(.*?)\s*</title>", re.IGNORECASE | re.DOTALL)
_SERVER_VERSION_RE = re.compile(r"(\S+)/(\d+(?:\.\d+)+)")
_JQUERY_SRC_RE = re.compile(r"jquery[.-](\d+\.\d+\.\d+)", re.IGNORECASE)
_JQUERY_BANNER_RE = re.compile(r"jQuery v(\d+\.\d+\.\d+)", re.IGNORECASE)


def _clip(text: str, limit: int = _RAW_LIMIT) -> str:
    text = (text or "").strip()
    if len(text) > limit:
        return text[:limit] + "\n...[truncated]"
    return text


def _is_host(h: str) -> bool:
    """Only probe hostnames/IPv4s; CIDR ranges need host enumeration first."""
    return h and "/" not in h and not h.startswith(":")


def dns_probe(host: str, timeout: int = _DNS_TIMEOUT_SECONDS) -> dict:
    """Resolve ``host`` via the system resolver. Real A/AAAA facts or a real error."""
    host = (host or "").strip().lower()
    if not _is_host(host):
        return {
            "status": "error",
            "observations": [],
            "log": f"[real_dns] Skipped host {host!r}: not a probeable hostname/IPv4.",
        }
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        obs = {
            "kind": "dns_error",
            "subject": host,
            "data": {"host": host, "error": str(exc)},
            "raw": f"{host} -> DNS resolution failed: {exc}",
        }
        return {
            "status": "success",
            "observations": [obs],
            "log": f"[real_dns] {host} did not resolve ({exc}).",
        }
    seen: set[str] = set()
    observations = []
    for _family, _stype, _proto, _canonname, sockaddr in infos:
        ip = sockaddr[0]
        if ip in seen:
            continue
        seen.add(ip)
        observations.append({
            "kind": "dns_record",
            "subject": host,
            "data": {"host": host, "ip": ip, "family": "A"},
            "raw": f"{host} -> A {ip}",
        })
    if not observations:
        observations.append({
            "kind": "dns_empty",
            "subject": host,
            "data": {"host": host},
            "raw": f"{host} -> resolver returned no A records",
        })
    log = f"[real_dns] Resolved {len(seen)} unique address(es) for {host}."
    return {"status": "success", "observations": observations, "log": log}


def tcp_probe(host: str, ports=None, timeout: int = _TCP_CONNECT_TIMEOUT_SECONDS) -> dict:
    """Real TCP connect handshake per port. open / closed / timeout are facts."""
    host = (host or "").strip().lower()
    if not _is_host(host):
        return {
            "status": "error",
            "observations": [],
            "log": f"[real_tcp] Skipped host {host!r}: not a probeable hostname/IPv4.",
        }
    port_list = ports or TCP_PORT_PROBE_LIST
    observations = []
    for port in port_list:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                state, detail = "open", "banner-grab skipped (passive)"
        except socket.timeout:
            state, detail = "filtered", f"connect to {host}:{port} timed out after {timeout}s"
            obs_kind = "tcp_timeout"
        except (ConnectionRefusedError, socket.error) as exc:
            state, detail = "closed", f"connection refused ({exc})"
            obs_kind = "tcp_closed"
        except OSError as exc:
            state, detail = "error", f"OS error ({exc})"
            obs_kind = "tcp_error"
            observations.append({
                "kind": obs_kind,
                "subject": host,
                "data": {"host": host, "port": port, "state": state, "detail": detail},
                "raw": f"{host}:{port} {state} - {detail}",
            })
            continue
        else:
            obs_kind = "tcp_open"

        observations.append({
            "kind": obs_kind,
            "subject": host,
            "data": {"host": host, "port": port, "state": state, "detail": detail},
            "raw": f"{host}:{port} {state} - {detail}",
        })

    open_ports = [o["data"]["port"] for o in observations if o["kind"] == "tcp_open"]
    log = f"[real_tcp] {len(open_ports)} open port(s) on {host}: {open_ports or 'none'}"
    return {"status": "success", "observations": observations, "log": log}


def _http_observations(url: str, status: int, headers: dict, body: str, error: str | None) -> list[dict]:
    host = url.split("://", 1)[-1].split("/", 1)[0]
    data = {
        "url": url,
        "scheme": url.split("://", 1)[0].lower(),
        "status_code": status,
    }
    if error is None:
        server = headers.get("Server") or headers.get("server") or ""
        title_match = _TITLE_RE.search(body or "")
        title = title_match.group(1).strip() if title_match else ""
        header_subset = {k: v for k, v in headers.items() if k.lower() in {
            "server", "content-security-policy", "strict-transport-security",
            "x-content-type-options", "x-frame-options", "x-powered-by",
        }}
        # Version hint from server banner or X-Powered-By / generator meta.
        version_hint = None
        srch = _SERVER_VERSION_RE.search(server or "")
        if srch:
            version_hint = f"{srch.group(1)} {srch.group(2)}"

        data.update({
            "title": title,
            "server": server,
            "version_hint": version_hint,
            "body_snippet": _clip(body, 600) if body else "",
            "has_csp": bool(headers.get("Content-Security-Policy") or headers.get("content-security-policy")),
            "has_hsts": bool(headers.get("Strict-Transport-Security") or headers.get("strict-transport-security")),
            "has_xcto": bool(headers.get("X-Content-Type-Options") or headers.get("x-content-type-options")),
            "has_xframe": bool(headers.get("X-Frame-Options") or headers.get("x-frame-options")),
            "headers": header_subset,
        })
        raw = (f"GET {url} -> {status} [{server}]"
               + (f" title={title!r}" if title else "")
               + "\n".join(f"  {k}: {v}" for k, v in header_subset.items())
               if header_subset else f"GET {url} -> {status} [{server}]")
        return [{
            "kind": "http_response",
            "subject": url,
            "data": data,
            "raw": _clip(raw),
        }]
    return [{
        "kind": "http_error",
        "subject": url,
        "data": {"url": url, "scheme": url.split("://", 1)[0].lower(), "error": error},
        "raw": f"GET {url} failed: {error}",
    }]


def http_probe(url: str, timeout: int = _HTTP_TIMEOUT_SECONDS) -> dict:
    """Real HTTP(S) GET; facts (status/headers/title/body) or a real error."""
    url = (url or "").strip()
    if not _is_host(url.split("://")[-1].split("/", 1)[0]):
        return {
            "status": "error",
            "observations": [],
            "log": f"[real_http] Skipped {url!r}: not a probeable URL.",
        }
    if "://" not in url:
        url = "https://" + url

    req = urllib.request.Request(url, headers={"User-Agent": "CyberAgent/3.0 (security audit)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(_HTTP_BODY_LIMIT + 1).decode("utf-8", errors="replace")[:_HTTP_BODY_LIMIT]
            headers = {k: v for k, v in resp.headers.items()}
            status = resp.status if hasattr(resp, "status") else resp.getcode()
            observations = _http_observations(url, status or 0, headers, body, None)
            observations.extend(body_match_observation(url, body))
    except urllib.error.HTTPError as exc:
        body = exc.read(_HTTP_BODY_LIMIT + 1).decode("utf-8", errors="replace")[:_HTTP_BODY_LIMIT]
        headers = {k: v for k, v in (exc.headers or {}).items()}
        observations = _http_observations(url, exc.code, headers, body, None)
    except urllib.error.URLError as exc:
        observations = _http_observations(url, 0, {}, "", str(exc.reason) if exc.reason else str(exc))
    except (ssl.SSLError, ConnectionError, socket.timeout, OSError) as exc:
        observations = _http_observations(url, 0, {}, "", f"{type(exc).__name__}: {exc}")

    status = observations[0]["data"].get("status_code") if observations else 0
    log = f"[real_http] GET {url} -> status {status}"
    return {"status": "success", "observations": observations, "log": log}


def extract_jquery_version(body: str) -> str | None:
    """Return an observed jQuery version string from page source, or None."""
    if not body:
        return None
    match = _JQUERY_SRC_RE.search(body) or _JQUERY_BANNER_RE.search(body)
    if not match:
        return None
    return match.group(1)


def body_match_observation(url: str, body: str) -> list[dict]:
    """Emit a ``body_match`` observation when an app-version fact is observed."""
    if not body:
        return []
    jq = extract_jquery_version(body)
    if not jq:
        return []
    return [{
        "kind": "body_match",
        "subject": url,
        "data": {"url": url, "match": "jquery_version", "version": jq},
        "raw": f"GET {url} body references jQuery {jq}",
    }]