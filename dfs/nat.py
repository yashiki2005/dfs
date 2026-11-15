#!/usr/bin/env python3
"""Zero-dependency UPnP IGD and NAT-PMP port mapping helpers for P2P NAT traversal."""

from __future__ import annotations

import ipaddress
import re
import socket
import struct
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple


def _default_gateway_ip() -> Optional[str]:
    """Return the default IPv4 gateway if discoverable, else None."""
    try:
        with open("/proc/net/route", "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[1] == "00000000":
                    gw = int(parts[2], 16)
                    return socket.inet_ntoa(struct.pack("<I", gw))
    except OSError:
        pass
    return None


def _local_ip_for_target(target_ip: str) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((target_ip, 9))
        return sock.getsockname()[0]
    except OSError:
        return "0.0.0.0"
    finally:
        sock.close()


def _natpmp_map(
    gateway_ip: str,
    internal_port: int,
    *,
    protocol: str = "UDP",
    lifetime: int = 3600,
    timeout: float = 1.5,
) -> Optional[Tuple[str, int]]:
    """Request a NAT-PMP (RFC 6886) port mapping and return (external_ip, external_port)."""
    proto_op = 1 if protocol.upper() == "UDP" else 2
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        # 1. Query external IPv4 address (version=0, op=0)
        sock.sendto(struct.pack("!BB", 0, 0), (gateway_ip, 5351))
        resp, _ = sock.recvfrom(64)
        if len(resp) < 12 or resp[1] != 128 or struct.unpack("!H", resp[2:4])[0] != 0:
            return None
        external_ip = socket.inet_ntoa(resp[8:12])
        if ipaddress.ip_address(external_ip).is_private:
            return None

        # 2. Request port mapping
        req = struct.pack("!BBHHHI", 0, proto_op, 0, internal_port, internal_port, lifetime)
        sock.sendto(req, (gateway_ip, 5351))
        mresp, _ = sock.recvfrom(64)
        if len(mresp) < 16 or struct.unpack("!H", mresp[2:4])[0] != 0:
            return None
        ext_port = struct.unpack("!H", mresp[10:12])[0]
        return external_ip, int(ext_port or internal_port)
    except OSError:
        return None
    finally:
        sock.close()


def _ssdp_discover_igd(timeout: float = 1.5) -> Optional[str]:
    """Send SSDP M-SEARCH for UPnP InternetGatewayDevice and return LOCATION URL."""
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
    ).encode("ascii")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)
    try:
        sock.sendto(msg, ("239.255.255.250", 1900))
        while True:
            data, _ = sock.recvfrom(4096)
            text = data.decode("utf-8", errors="ignore")
            m = re.search(r"^LOCATION:\s*(\S+)", text, re.IGNORECASE | re.MULTILINE)
            if m:
                return m.group(1).strip()
    except OSError:
        return None
    finally:
        sock.close()


def _find_wan_control_url(location_url: str, timeout: float = 2.0) -> Optional[Tuple[str, str]]:
    """Fetch IGD root XML and return (control_url, service_type)."""
    try:
        with urllib.request.urlopen(location_url, timeout=timeout) as resp:
            xml_bytes = resp.read(256 * 1024)
        root = ET.fromstring(xml_bytes)
    except (OSError, urllib.error.URLError, ET.ParseError):
        return None

    target_types = (
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANIPConnection:2",
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
    )
    for elem in root.iter():
        if not elem.tag.endswith("service"):
            continue
        stype = ""
        ctrl = ""
        for child in elem:
            if child.tag.endswith("serviceType") and child.text:
                stype = child.text.strip()
            elif child.tag.endswith("controlURL") and child.text:
                ctrl = child.text.strip()
        if stype in target_types and ctrl:
            return urllib.parse.urljoin(location_url, ctrl), stype
    return None


def _upnp_soap_call(
    control_url: str,
    service_type: str,
    action: str,
    body_xml: str,
    timeout: float = 2.0,
) -> Optional[str]:
    envelope = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        f'<s:Body><u:{action} xmlns:u="{service_type}">{body_xml}</u:{action}></s:Body>'
        "</s:Envelope>"
    ).encode("utf-8")
    req = urllib.request.Request(
        control_url,
        data=envelope,
        method="POST",
        headers={
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPACTION": f'"{service_type}#{action}"',
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read(64 * 1024).decode("utf-8", errors="ignore")
    except (OSError, urllib.error.URLError):
        return None


class UPnPPortMapper:
    """Manages best-effort UPnP IGD / NAT-PMP mappings for DFS P2P ports."""

    def __init__(self, *, timeout: float = 1.5) -> None:
        self.timeout = float(timeout)
        self._igd: Optional[Tuple[str, str]] = None
        self._mapped: List[Tuple[int, str]] = []
        self.external_ip: Optional[str] = None

    def map_port(
        self,
        internal_port: int,
        *,
        protocol: str = "UDP",
        description: str = "dfs-p2p",
        lifetime: int = 3600,
    ) -> Optional[Tuple[str, int]]:
        proto = protocol.upper()
        # 1. Try UPnP IGD
        if self._igd is None:
            loc = _ssdp_discover_igd(timeout=self.timeout)
            if loc:
                self._igd = _find_wan_control_url(loc, timeout=self.timeout)
        if self._igd is not None:
            ctrl_url, stype = self._igd
            parsed = urllib.parse.urlsplit(ctrl_url)
            local_ip = _local_ip_for_target(parsed.hostname or "192.168.0.1")
            add_body = (
                "<NewRemoteHost></NewRemoteHost>"
                f"<NewExternalPort>{internal_port}</NewExternalPort>"
                f"<NewProtocol>{proto}</NewProtocol>"
                f"<NewInternalPort>{internal_port}</NewInternalPort>"
                f"<NewInternalClient>{local_ip}</NewInternalClient>"
                "<NewEnabled>1</NewEnabled>"
                f"<NewPortMappingDescription>{description}</NewPortMappingDescription>"
                f"<NewLeaseDuration>{lifetime}</NewLeaseDuration>"
            )
            if _upnp_soap_call(ctrl_url, stype, "AddPortMapping", add_body, timeout=self.timeout) is not None:
                ext_xml = _upnp_soap_call(
                    ctrl_url, stype, "GetExternalIPAddress", "", timeout=self.timeout
                )
                if ext_xml:
                    m = re.search(r"<NewExternalIPAddress>([^<]+)</NewExternalIPAddress>", ext_xml)
                    if m:
                        ext_ip = m.group(1).strip()
                        try:
                            if not ipaddress.ip_address(ext_ip).is_private:
                                self.external_ip = ext_ip
                                self._mapped.append((internal_port, proto))
                                return ext_ip, internal_port
                        except ValueError:
                            pass

        # 2. Fallback to NAT-PMP
        gw = _default_gateway_ip()
        if gw:
            res = _natpmp_map(gw, internal_port, protocol=proto, lifetime=lifetime, timeout=self.timeout)
            if res is not None:
                self.external_ip = res[0]
                return res
        return None

    def close(self) -> None:
        if self._igd is not None:
            ctrl_url, stype = self._igd
            for port, proto in list(self._mapped):
                del_body = (
                    "<NewRemoteHost></NewRemoteHost>"
                    f"<NewExternalPort>{port}</NewExternalPort>"
                    f"<NewProtocol>{proto}</NewProtocol>"
                )
                _upnp_soap_call(ctrl_url, stype, "DeletePortMapping", del_body, timeout=1.0)
        self._mapped.clear()
