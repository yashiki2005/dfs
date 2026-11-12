#!/usr/bin/env python3
"""DNSSEC discovery のレコード検証と CLI 連携。"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dfs5 import cli_main
from dfs5.dnssec import (
    Discovery,
    DiscoveryError,
    RegistryEndpoint,
    discover_domain,
    parse_discovery_text,
)
from dfs5.remotes import RemoteStore


ROOT_PUB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestRootKey"


def _record(**overrides):
    data = {
        "schema": "dfs5-discovery-v1",
        "domain": "example.com",
        "root_anchor": "/example.com",
        "root_pubkey": ROOT_PUB,
        "registries": [
            {"url": "https://l2-a.example.com:9440", "role": "primary"},
            {"url": "https://l2-b.example.com:9440", "role": "secondary"},
        ],
        "epoch": 1,
        "ttl": 300,
    }
    data.update(overrides)
    return json.dumps(data)


class TestDiscoveryParser(unittest.TestCase):
    def test_valid_record(self) -> None:
        d = parse_discovery_text(_record(), expected_domain="example.com")
        self.assertEqual(d.domain, "example.com")
        self.assertEqual(d.primary_url, "https://l2-a.example.com:9440")
        self.assertEqual(d.alternate_urls, ["https://l2-b.example.com:9440"])
        self.assertEqual(d.epoch, 1)

    def test_requires_exactly_one_primary(self) -> None:
        bad = _record(
            registries=[
                {"url": "https://a.example.com:9440", "role": "primary"},
                {"url": "https://b.example.com:9440", "role": "primary"},
            ]
        )
        with self.assertRaises(DiscoveryError):
            parse_discovery_text(bad)

    def test_rejects_bad_schema_and_root(self) -> None:
        with self.assertRaises(DiscoveryError):
            parse_discovery_text(_record(schema="other"))
        with self.assertRaises(DiscoveryError):
            parse_discovery_text(_record(root_pubkey="not-a-key"))
        with self.assertRaises(DiscoveryError):
            parse_discovery_text(_record(registries=[]))

    def test_domain_mismatch_is_rejected(self) -> None:
        with self.assertRaises(DiscoveryError):
            parse_discovery_text(_record(), expected_domain="other.example")


class TestDiscoverDomain(unittest.TestCase):
    def _answer(self, *, authenticated: bool):
        import dns.flags

        class Rdata:
            strings = [_record().encode("utf-8")]

        class Response:
            flags = dns.flags.AD if authenticated else 0

        class Answer(list):
            response = Response()

        class Resolver:
            def __init__(self, configure: bool = True):
                self.lifetime = 0

            def resolve(self, _name, _rtype):
                return Answer([Rdata()])

        return Resolver

    def test_requires_ad_bit_by_default(self) -> None:
        resolver = self._answer(authenticated=False)
        with patch("dns.resolver.Resolver", resolver):
            with self.assertRaises(DiscoveryError):
                discover_domain("example.com")
        resolver = self._answer(authenticated=True)
        with patch("dns.resolver.Resolver", resolver):
            d = discover_domain("example.com")
        self.assertEqual(d.primary.role, "primary")

    def test_no_ad_option_accepts_trusted_local_resolver(self) -> None:
        resolver = self._answer(authenticated=False)
        with patch("dns.resolver.Resolver", resolver):
            d = discover_domain("example.com", require_ad=False)
        self.assertEqual(d.domain, "example.com")


class TestDnssecCli(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="dfs5_dnssec_")
        self.base = Path(self._tmp.name)
        self.key = self.base / "writer"
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(self.key)],
            check=True,
            capture_output=True,
        )
        self.root_key = self.base / "root"
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(self.root_key)],
            check=True,
            capture_output=True,
        )
        self.root_pub = Path(f"{self.root_key}.pub").read_text(encoding="utf-8").strip()
        self.config_file = self.base / "remotes.json"
        self.old_config = os.environ.get("DFS5_CONFIG")
        os.environ["DFS5_CONFIG"] = str(self.config_file)
        self.discovery = Discovery(
            domain="example.com",
            root_anchor="/example.com",
            root_pubkey=self.root_pub,
            registries=(
                RegistryEndpoint("http://primary.example.com:9440", "primary"),
                RegistryEndpoint("http://secondary.example.com:9440", "secondary"),
            ),
            epoch=3,
            ttl=300,
            raw={},
        )

    def tearDown(self) -> None:
        if self.old_config is None:
            os.environ.pop("DFS5_CONFIG", None)
        else:
            os.environ["DFS5_CONFIG"] = self.old_config
        self._tmp.cleanup()

    def test_config_create_uses_dnssec_registry_and_root(self) -> None:
        with patch.object(cli_main, "discover_domain", return_value=self.discovery):
            rc = cli_main.main([
                "config", "create", "dns",
                "--dnssec-domain", "example.com",
                "--key", str(self.key),
                "--secret", "secret",
                "--no-prompt",
            ])
        self.assertEqual(rc, 0)
        remote = RemoteStore(self.config_file).get("dns")
        self.assertEqual(remote.registry, "http://primary.example.com:9440")
        self.assertEqual(remote.registry_alternates, ["http://secondary.example.com:9440"])
        self.assertEqual(remote.root_pubkey, self.root_pub)

    def test_explicit_registry_conflict_is_rejected(self) -> None:
        with patch.object(cli_main, "discover_domain", return_value=self.discovery):
            rc = cli_main.main([
                "config", "create", "dns",
                "--dnssec-domain", "example.com",
                "--registry", "http://other.example.com:9440",
                "--key", str(self.key),
                "--secret", "secret",
                "--no-prompt",
            ])
        self.assertEqual(rc, 2)

    def test_discover_command(self) -> None:
        with patch.object(cli_main, "discover_domain", return_value=self.discovery):
            self.assertEqual(cli_main.main(["discover", "example.com"]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
