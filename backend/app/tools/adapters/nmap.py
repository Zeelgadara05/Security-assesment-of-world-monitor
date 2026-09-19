"""nmap adapter -- XML output normalized into host/port/service observations."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from app.observations import types
from app.tools.adapters.base import ExternalToolAdapter, ToolObservation, ToolParseError


class NmapAdapter(ExternalToolAdapter):
    tool_name = "nmap"
    binary = "nmap"
    output_format = "xml"

    def build_command(self, target: str, options: dict) -> list[str]:
        command = ["nmap", "-sV", "-T4"]
        ports = options.get("ports")
        if ports:
            command += ["-p", str(ports)]
        command += ["-oX", "-", target]
        return command

    def parse(self, stdout: str, target: str) -> list[ToolObservation]:
        text = stdout or ""
        start = text.find("<nmaprun")
        if start == -1:
            raise ToolParseError("no <nmaprun> element in nmap output")
        try:
            root = ET.fromstring(text[start:])
        except ET.ParseError as exc:
            raise ToolParseError(f"malformed nmap XML: {exc}") from exc

        observations: list[ToolObservation] = []
        for host in root.findall("host"):
            addr = host.find("address")
            ip = addr.get("addr") if addr is not None else target
            hostnames = [
                h.get("name")
                for h in host.findall("hostnames/hostname")
                if h.get("name")
            ]
            subject = hostnames[0] if hostnames else ip
            observations.append(ToolObservation(
                types.OBS_HOST, subject,
                data={"ip": ip, "hostnames": hostnames},
                discriminator={"ip": ip},
            ))
            for port in host.findall("ports/port"):
                proto = port.get("protocol", "tcp")
                portid = int(port.get("portid") or 0)
                state_el = port.find("state")
                state = state_el.get("state") if state_el is not None else "unknown"
                service_el = port.find("service")
                service = service_el.get("name") if service_el is not None else None
                observations.append(ToolObservation(
                    types.OBS_PORT, subject,
                    data={"port": portid, "protocol": proto, "state": state, "service": service},
                    discriminator={"port": portid, "protocol": proto},
                ))
                if service_el is not None:
                    observations.append(ToolObservation(
                        types.OBS_SERVICE, subject,
                        data={
                            "port": portid,
                            "protocol": proto,
                            "name": service_el.get("name"),
                            "product": service_el.get("product"),
                            "version": service_el.get("version"),
                            "extrainfo": service_el.get("extrainfo"),
                        },
                        discriminator={"port": portid, "protocol": proto},
                    ))
        return observations
