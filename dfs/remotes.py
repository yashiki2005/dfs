#!/usr/bin/env python3
"""
dfs/remotes.py
rclone ライク CLI のためのリモート定義の保存と取り出し。

`~/.config/dfs/remotes.json` に「名前 -> 接続情報」を置く。1 つのリモートは
L2 名簿の URL・L3 OST の host:port・サブツリーのパス・書き手鍵・tree_secret・
作業ディレクトリを持つ。`remote:path` の形で参照する。
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .crypto import normalize_path
from .paths import cache_dir, config_dir, restrict_to_owner

CONFIG_ENV = "DFS_CONFIG"
DEFAULT_CONFIG = "~/.config/dfs/remotes.json"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")

# ``ost`` は必須にしない。L2 のロケータ（``endpoints``）から引けるため、
# 指定が無ければ最初の版を読むときに解決する。``path`` も同様に省略できる
# （その場合は「作業ディレクトリをリモートの根として使う」＝ rclone の `remote:` 相当）。
REQUIRED_FIELDS = ("registry", "key")


class RemoteError(Exception):
    """リモート定義の誤り"""


@dataclass
class Remote:
    """1 つのリモート（= 1 つの書き込み境界）の定義。"""

    name: str
    registry: str                       # L2 名簿 URL（例: http://172.16.1.60:19440）
    key: str                            # 書き手の OpenSSH Ed25519 秘密鍵
    registry_alternates: List[str] = field(default_factory=list)  # 読み取り用の代替名簿
    ost: str = ""                       # L3 OST の host:port。空ならロケータから解決する
    ost_alternates: List[str] = field(default_factory=list)  # 読み取り用の複製 OST
    libp2p_peers: List[str] = field(default_factory=list)  # 読み取り用 libp2p QUIC peer
    libp2p_psk: str = ""                 # private swarm 用 pre-shared key
    path: str = ""                      # サブツリーのパス。空ならロケータの path を使う
    secret: str = ""                    # tree_secret。空なら --secret を後で渡す
    workdir: str = ""                   # 作業ディレクトリ（既定: ~/.cache/dfs/<name>）
    epoch: int = 1                      # 委譲のエポック
    role_epoch: int = 1                 # registry primary/secondary の fencing 世代
    compression: str = "auto"           # フォルダ xattr が無い場合の既定圧縮
    node_name: str = ""                 # 端末名（既定: リモート名）
    root_pubkey: str = ""               # root アンカーの公開鍵（信頼の根。TOFU で記録）
    root_fingerprint: str = ""          # 表示・比較用の指紋
    ost_cert_sha256: str = ""           # L3 OST の TLS 証明書 SHA-256 ピン
    allow_tofu: bool = False            # True のときのみ root_pubkey 未設定時の TOFU を許可
    read_only: bool = False             # True のときは秘密鍵を持たず読み取り専用にする

    def resolved_workdir(self) -> Path:
        if self.workdir:
            return Path(self.workdir).expanduser()
        return cache_dir() / self.name

    def to_dict(self) -> dict:
        d = asdict(self)
        d["node_name"] = self.node_name or self.name
        return d

    def registry_urls(self) -> List[str]:
        """主名簿を先頭にした、重複なしの読み取り候補。"""
        urls = [self.registry, *self.registry_alternates]
        seen = set()
        result = []
        for url in urls:
            value = str(url or "").strip().rstrip("/")
            if value and value not in seen:
                seen.add(value)
                result.append(value)
        return result

    @classmethod
    def from_dict(cls, data: dict) -> "Remote":
        read_only = bool(data.get("read_only", False))
        req = ("name", "registry") if read_only else ("name",) + REQUIRED_FIELDS
        missing = [f for f in req if not data.get(f)]
        if missing:
            raise RemoteError(f"Remote definition is missing fields: {', '.join(missing)}")
        raw_path = str(data.get("path", "") or "")
        raw_alternates = data.get("registry_alternates") or []
        if isinstance(raw_alternates, str):
            raw_alternates = [raw_alternates]
        raw_ost_alternates = data.get("ost_alternates") or []
        if isinstance(raw_ost_alternates, str):
            raw_ost_alternates = [raw_ost_alternates]
        raw_libp2p_peers = data.get("libp2p_peers") or []
        if isinstance(raw_libp2p_peers, str):
            raw_libp2p_peers = [raw_libp2p_peers]
        return cls(
            name=str(data["name"]),
            registry=str(data["registry"]),
            key=str(data.get("key", "") or ""),
            registry_alternates=[str(u) for u in raw_alternates if str(u).strip()],
            ost=str(data.get("ost", "") or ""),
            ost_alternates=[
                cls.normalize_ost(str(u))
                for u in raw_ost_alternates
                if str(u).strip()
            ],
            libp2p_peers=[str(p) for p in raw_libp2p_peers if str(p).strip()],
            libp2p_psk=str(data.get("libp2p_psk", "") or ""),
            path=normalize_path(raw_path) if raw_path else "",
            secret=str(data.get("secret", "") or ""),
            workdir=str(data.get("workdir", "")),
            epoch=int(data.get("epoch", 1)),
            role_epoch=int(data.get("role_epoch", 1)),
            compression=str(data.get("compression", "auto") or "auto"),
            node_name=str(data.get("node_name", "") or data["name"]),
            root_pubkey=str(data.get("root_pubkey", "") or ""),
            root_fingerprint=str(data.get("root_fingerprint", "") or ""),
            ost_cert_sha256=str(data.get("ost_cert_sha256", "") or "").strip().lower(),
            allow_tofu=bool(data.get("allow_tofu", False)),
            read_only=read_only,
        )

    @staticmethod
    def normalize_ost(endpoint: str) -> str:
        """ロケータの endpoint（``tls://host:port`` や ``https://...``）を正規化する。"""
        value = endpoint.strip()
        if value.startswith("http://") or value.startswith("https://"):
            return value.rstrip("/")
        if value.startswith("tls://"):
            value = value[len("tls://"):]
        return value.rstrip("/")


def config_path() -> Path:
    raw = os.environ.get(CONFIG_ENV)
    if raw:
        return Path(raw).expanduser()
    return config_dir() / "remotes.json"


class RemoteStore:
    """リモート定義の集合。JSON 1 ファイルに保存する。"""

    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path is not None else config_path()
        self.remotes: Dict[str, Remote] = {}
        self.load()

    def load(self) -> None:
        self.remotes = {}
        if not self.path.is_file():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise RemoteError(f"Config file {self.path} is not valid JSON: {e}") from e
        for name, item in (raw.get("remotes") or {}).items():
            data = dict(item)
            data.setdefault("name", name)
            self.remotes[name] = Remote.from_dict(data)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": "dfs-remotes-v1",
            "remotes": {name: r.to_dict() for name, r in sorted(self.remotes.items())},
        }
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        restrict_to_owner(tmp)
        tmp.replace(self.path)

    def get(self, name: str) -> Remote:
        if name not in self.remotes:
            known = ", ".join(sorted(self.remotes)) or "(none)"
            hint = (
                " (hint: pass a remote name like 'dfs://local/path', not a subtree path)"
                if name.startswith("/")
                else ""
            )
            raise RemoteError(f"Unknown remote {name!r}. Known remotes: {known}{hint}")
        return self.remotes[name]

    def set(self, remote: Remote) -> None:
        if not NAME_RE.match(remote.name):
            raise RemoteError(
                f"Invalid remote name {remote.name!r}: use letters, digits, '_', '.', '-'"
            )
        self.remotes[remote.name] = remote
        self.save()

    def delete(self, name: str) -> bool:
        if name in self.remotes:
            del self.remotes[name]
            self.save()
            return True
        return False

    def names(self) -> List[str]:
        return sorted(self.remotes)


def split_remote_spec(spec: str, default_remote: Optional[str] = None) -> tuple[str, str]:
    """``dfs://<remote>/<path>``、``dfs://<remote>:<path>``、または ``<remote>:<path>`` を (リモート名, パス) に分ける。

    ``:path`` や ``dfs:///path`` だけなら ``default_remote`` を使う。
    ``remote:`` や ``dfs://remote/``、``dfs://remote:`` はパスが空。
    """
    if spec.startswith("dfs://"):
        rest = spec[len("dfs://"):]
        if ":" in rest and "/" not in rest.split(":", 1)[0]:
            name, _, sub = rest.partition(":")
            name = name or (default_remote or "")
            if not name:
                raise RemoteError(f"Remote name is required in {spec!r} (or pass --remote)")
            return name, sub.lstrip("/")
        from urllib.parse import urlsplit

        parsed = urlsplit(spec)
        name = parsed.netloc or (default_remote or "")
        if not name:
            raise RemoteError(f"Remote name is required in {spec!r} (or pass --remote)")
        return name, parsed.path.lstrip("/")
    if ":" in spec:
        name, _, sub = spec.partition(":")
        name = name or (default_remote or "")
        if not name:
            raise RemoteError(f"Remote name is required in {spec!r} (or pass --remote)")
        return name, sub.lstrip("/")
    if not default_remote:
        raise RemoteError(
            f"Cannot tell if {spec!r} is a remote or a local path. "
            "Use 'dfs://remote/path', 'remote:path', or pass --remote."
        )
    return default_remote, spec.lstrip("/")
