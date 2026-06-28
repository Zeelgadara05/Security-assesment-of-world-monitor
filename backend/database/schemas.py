import re
import socket
import urllib.parse
from pydantic import BaseModel, field_validator, ValidationInfo

class ScanRequest(BaseModel):
    target: str

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Target cannot be empty")

        # Strip HTTP/HTTPS protocols if provided
        parsed = urllib.parse.urlparse(v)
        hostname = parsed.netloc or parsed.path
        if not hostname:
            hostname = v

        # Split host:port if specified
        if ":" in hostname:
            hostname = hostname.split(":")[0]

        # Validations for Domain, IP address, CIDR
        # 1. Check IP address (IPv4)
        ip_regex = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        if re.match(ip_regex, hostname):
            return hostname

        # 2. Check CIDR (IPv4/subnet)
        cidr_regex = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(3[0-2]|[1-2]?[0-9])$"
        if re.match(cidr_regex, hostname):
            return hostname

        # 3. Check Domain Name
        domain_regex = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
        if re.match(domain_regex, hostname):
            return hostname

        raise ValueError("Invalid target format. Must be a valid domain name, IPv4 address, or CIDR block.")
