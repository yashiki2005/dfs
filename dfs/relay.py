#!/usr/bin/env python3
"""
dfs/relay.py
NAT / ファイアウォール裏の単一書き手 dfssvc を root ホスト経由で中継するリレー機構。
"""

from __future__ import annotations

import hmac
import http.client
import json
import os
import queue
import re
import ssl
import struct
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlencode, urlsplit

NODE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
DEFAULT_PULL_WAIT_SECONDS = 25.0
DEFAULT_FORWARD_TIMEOUT = 35.0
DEFAULT_NODE_TTL_SECONDS = 90.0
DEFAULT_MAX_NODES = 1024
DEFAULT_MAX_PENDING_PER_NODE = 256


class RelayError(Exception):
    """リレー制御・フレーム形式の基底エラー"""


class RelayAuthError(RelayError):
    """リレートークン認証エラー"""


class RelayNodeOfflineError(RelayError):
    """対象ノードがリレーに接続していない"""


class RelayTimeoutError(RelayError):
    """対象ノードからの応答待ちタイムアウト"""


def validate_node_id(node_id: str) -> str:
    text = str(node_id or "").strip()
    if not NODE_ID_RE.match(text):
        raise ValueError(f"Invalid relay node_id: {node_id!r}")
    return text


def encode_relay_frame(header: Dict[str, Any], body: bytes = b"") -> bytes:
    """``[4B header_len][UTF-8 JSON header][raw body]`` にパックする。"""
    hdr_bytes = json.dumps(header, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return struct.pack(">I", len(hdr_bytes)) + hdr_bytes + body


def decode_relay_frame(raw: bytes) -> Tuple[Dict[str, Any], bytes]:
    """``encode_relay_frame`` でパックされたバイナリを展開する。"""
    if len(raw) < 4:
        raise RelayError("Truncated relay frame")
    hdr_len = struct.unpack(">I", raw[:4])[0]
    if 4 + hdr_len > len(raw):
        raise RelayError("Truncated relay frame header")
    try:
        header = json.loads(raw[4 : 4 + hdr_len].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise RelayError(f"Malformed relay frame header: {e}") from e
    if not isinstance(header, dict):
        raise RelayError("Relay frame header must be a JSON object")
    return header, raw[4 + hdr_len :]


@dataclass
class RelayRequest:
    id: str
    method: str
    path: str
    content_type: str
    body: bytes
    headers: Dict[str, str] = field(default_factory=dict)
    event: threading.Event = field(default_factory=threading.Event)
    status: int = 502
    resp_content_type: str = "application/json"
    resp_body: bytes = b""


class _NodeSlot:
    def __init__(self) -> None:
        self.pending: queue.Queue[RelayRequest] = queue.Queue()
        self.inflight: Dict[str, RelayRequest] = {}
        self.last_seen: float = time.monotonic()
        self.active_pullers: int = 0
        self.observed_ip: str = ""
        self.direct_endpoints: List[str] = []
        self.role: str = "writer"
        self.peer_id: str = ""
        self.p2p_addrs: List[str] = []


class RelayHub:
    """root dfssvc 側で動く HTTP リバースリレーハブ。"""

    def __init__(
        self,
        token: str = "",
        node_ttl: float = DEFAULT_NODE_TTL_SECONDS,
        max_nodes: int = DEFAULT_MAX_NODES,
        max_pending_per_node: int = DEFAULT_MAX_PENDING_PER_NODE,
    ) -> None:
        self.token = str(token or "")
        self.node_ttl = float(node_ttl)
        self.max_nodes = max(1, int(max_nodes))
        self.max_pending_per_node = max(1, int(max_pending_per_node))
        self._lock = threading.RLock()
        self._nodes: Dict[str, _NodeSlot] = {}
        self._allowed_peer_ids: Dict[str, Dict[str, Any]] = {}
        self.on_allowlist_change: Optional[Any] = None

    def verify_token(self, presented: Optional[str]) -> None:
        if not self.token:
            return
        if not presented or not hmac.compare_digest(presented, self.token):
            raise RelayAuthError("Invalid or missing X-DFS-Relay-Token")

    def _prune_expired_locked(self, now: Optional[float] = None) -> None:
        cur = time.monotonic() if now is None else now
        expired = [
            nid
            for nid, slot in self._nodes.items()
            if slot.active_pullers == 0
            and not slot.inflight
            and (cur - slot.last_seen) > self.node_ttl
        ]
        for nid in expired:
            del self._nodes[nid]

    def _get_or_create_slot(self, node_id: str) -> _NodeSlot:
        validate_node_id(node_id)
        with self._lock:
            self._prune_expired_locked()
            slot = self._nodes.get(node_id)
            if slot is None:
                if len(self._nodes) >= self.max_nodes:
                    raise RelayError("Relay hub node capacity exceeded")
                slot = _NodeSlot()
                self._nodes[node_id] = slot
            return slot

    def pull_next(
        self,
        node_id: str,
        wait_seconds: float = DEFAULT_PULL_WAIT_SECONDS,
        observed_ip: str = "",
        direct_endpoints: Optional[Sequence[str]] = None,
    ) -> Optional[RelayRequest]:
        slot = self._get_or_create_slot(node_id)
        with self._lock:
            slot.last_seen = time.monotonic()
            slot.active_pullers += 1
            if observed_ip:
                slot.observed_ip = str(observed_ip).strip()
            if direct_endpoints is not None:
                cleaned = [str(ep).strip() for ep in direct_endpoints if str(ep).strip()]
                if cleaned:
                    slot.direct_endpoints = cleaned
        try:
            req = slot.pending.get(timeout=max(0.1, float(wait_seconds)))
            with self._lock:
                slot.last_seen = time.monotonic()
            return req
        except queue.Empty:
            with self._lock:
                slot.last_seen = time.monotonic()
            return None
        finally:
            with self._lock:
                slot.active_pullers = max(0, slot.active_pullers - 1)

    def deliver_reply(
        self,
        node_id: str,
        req_id: str,
        status: int,
        content_type: str,
        body: bytes,
    ) -> bool:
        validate_node_id(node_id)
        with self._lock:
            slot = self._nodes.get(node_id)
            if slot is None:
                return False
            slot.last_seen = time.monotonic()
            req = slot.inflight.pop(req_id, None)
        if req is None:
            return False
        req.status = int(status)
        req.resp_content_type = content_type or "application/octet-stream"
        req.resp_body = body
        req.event.set()
        return True

    def forward(
        self,
        node_id: str,
        method: str,
        sub_path: str,
        content_type: str,
        body: bytes,
        timeout: float = DEFAULT_FORWARD_TIMEOUT,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, str, bytes]:
        validate_node_id(node_id)
        with self._lock:
            slot = self._nodes.get(node_id)
            if slot is None:
                raise RelayNodeOfflineError(f"Relay node {node_id!r} is not connected")
            age = time.monotonic() - slot.last_seen
            if slot.active_pullers == 0 and age > self.node_ttl:
                raise RelayNodeOfflineError(f"Relay node {node_id!r} is offline")
            if slot.pending.qsize() >= self.max_pending_per_node:
                raise RelayError(f"Relay node {node_id!r} pending queue is full")
            req = RelayRequest(
                id=uuid.uuid4().hex,
                method=method.upper(),
                path=sub_path,
                content_type=content_type or "application/octet-stream",
                body=body,
                headers=dict(headers or {}),
            )
            slot.inflight[req.id] = req
            slot.pending.put(req)

        if not req.event.wait(timeout=max(0.5, float(timeout))):
            with self._lock:
                if slot is not None:
                    slot.inflight.pop(req.id, None)
            raise RelayTimeoutError(f"Relay node {node_id!r} timed out")
        return req.status, req.resp_content_type, req.resp_body

    def status_snapshot(self) -> Dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            nodes = []
            for nid, slot in sorted(self._nodes.items()):
                nodes.append({
                    "node_id": nid,
                    "active_pullers": slot.active_pullers,
                    "last_seen_ago_s": round(max(0.0, now - slot.last_seen), 2),
                    "pending": slot.pending.qsize(),
                    "inflight": len(slot.inflight),
                })
        return {"nodes": nodes}

    def get_ice_candidates(self, node_id: Optional[str] = None) -> Dict[str, Any]:
        """ICE 方式でクライアントに返す接続候補（host / srflx / relay）を優先度順に生成する。

        ``node_id`` が未指定の場合はオンラインな全ノードの候補を集約して返す。
        """
        if not node_id:
            with self._lock:
                node_ids = sorted(self._nodes.keys())
            nodes: List[Dict[str, Any]] = []
            agg_candidates: List[Dict[str, Any]] = []
            seen_eps: set[str] = set()
            for nid in node_ids:
                info = self.get_ice_candidates(nid)
                if not info.get("online"):
                    continue
                nodes.append(info)
                for cand in info.get("candidates", []):
                    ep = str(cand.get("endpoint") or "")
                    if ep and ep not in seen_eps:
                        seen_eps.add(ep)
                        agg_candidates.append(cand)
            agg_candidates.sort(key=lambda c: int(c.get("priority", 0)), reverse=True)
            return {"nodes": nodes, "candidates": agg_candidates}

        nid = validate_node_id(node_id)
        now = time.monotonic()
        with self._lock:
            slot = self._nodes.get(nid)
            if slot is None:
                return {
                    "node_id": nid,
                    "observed_ip": "",
                    "online": False,
                    "candidates": [
                        {"type": "relay", "endpoint": f"/relay/{nid}", "priority": 10}
                    ],
                }
            online = (slot.active_pullers > 0) or ((now - slot.last_seen) <= self.node_ttl)
            observed_ip = slot.observed_ip
            direct_eps = list(slot.direct_endpoints)
            role = slot.role
            peer_id = slot.peer_id
            p2p_addrs = list(slot.p2p_addrs)

        candidates: List[Dict[str, Any]] = []
        seen: set[str] = set()
        for addr in p2p_addrs:
            if addr not in seen:
                seen.add(addr)
                candidates.append({
                    "type": "libp2p",
                    "endpoint": addr,
                    "peer_id": peer_id,
                    "priority": 120,
                })
        for ep in direct_eps:
            if ep not in seen:
                seen.add(ep)
                candidates.append({"type": "host", "endpoint": ep, "priority": 100})
        if observed_ip:
            for ep in direct_eps:
                parts = urlsplit(ep)
                if parts.scheme in ("http", "https") and parts.port:
                    srflx_ep = f"{parts.scheme}://{observed_ip}:{parts.port}{parts.path.rstrip('/')}"
                    if srflx_ep not in seen:
                        seen.add(srflx_ep)
                        candidates.append({"type": "srflx", "endpoint": srflx_ep, "priority": 50})
                    break
        candidates.append({"type": "relay", "endpoint": f"/relay/{nid}", "priority": 10})
        return {
            "node_id": nid,
            "role": role,
            "observed_ip": observed_ip,
            "online": online,
            "peer_id": peer_id,
            "p2p_addrs": p2p_addrs,
            "candidates": candidates,
        }

    def allow_peer_id(
        self,
        peer_id: str,
        node_id: str = "",
        role: str = "seeder",
        addrs: Optional[Sequence[str]] = None,
        sync_id: str = "",
        sub_path: str = "",
    ) -> Dict[str, Any]:
        """ドメイン内の許可済み libp2p PeerID リストへ登録する。"""
        pid = str(peer_id or "").strip()
        if not pid:
            raise ValueError("peer_id is required")
        cleaned_addrs = [str(a).strip() for a in (addrs or ()) if str(a).strip()]
        cleaned_node_id = str(node_id or "").strip()
        cleaned_sync_id = str(sync_id or "").strip()
        with self._lock:
            if cleaned_node_id and cleaned_node_id not in ("hub", "seeder", "primary", "secondary"):
                stale_pids = [
                    k for k, v in self._allowed_peer_ids.items()
                    if k != pid and v.get("node_id") == cleaned_node_id
                ]
                for sp in stale_pids:
                    self._allowed_peer_ids.pop(sp, None)
            existing = self._allowed_peer_ids.get(pid, {})
            entry = {
                "peer_id": pid,
                "node_id": str(cleaned_node_id or existing.get("node_id") or "").strip(),
                "role": str(role or existing.get("role") or "seeder"),
                "addrs": cleaned_addrs or list(existing.get("addrs") or []),
                "sync_id": str(cleaned_sync_id or existing.get("sync_id") or "").strip(),
                "sub_path": str(sub_path or existing.get("sub_path") or "").strip(),
                "updated_at": time.time(),
            }
            self._allowed_peer_ids[pid] = entry
            cb = self.on_allowlist_change
            ids = sorted(self._allowed_peer_ids.keys())
        if callable(cb):
            try:
                cb(ids)
            except Exception:
                pass
        return dict(entry)

    def revoke_peer_id(self, peer_id: str) -> bool:
        """ドメイン内の許可済み libp2p PeerID リストから削除する。"""
        pid = str(peer_id or "").strip()
        with self._lock:
            removed = self._allowed_peer_ids.pop(pid, None) is not None
            cb = self.on_allowlist_change
            ids = sorted(self._allowed_peer_ids.keys())
        if removed and callable(cb):
            try:
                cb(ids)
            except Exception:
                pass
        return removed

    def is_peer_id_allowed(self, peer_id: str) -> bool:
        pid = str(peer_id or "").strip()
        with self._lock:
            return bool(pid and pid in self._allowed_peer_ids)

    def get_allowed_peers(self) -> Dict[str, Any]:
        """ドメイン内の許可済み PeerID とマルチアドレス一覧を返す。"""
        with self._lock:
            peers = [dict(v) for v in self._allowed_peer_ids.values()]
            peer_ids = sorted(self._allowed_peer_ids.keys())
        return {"peer_ids": peer_ids, "peers": peers}

    def announce_peer(
        self,
        node_id: str,
        direct_endpoints: Sequence[str],
        observed_ip: str = "",
        role: str = "seeder",
        peer_id: str = "",
        p2p_addrs: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """読者キャッシュ（seeder）やミラーが軽量トラッカーへ読み取りエンドポイントを登録する。"""
        slot = self._get_or_create_slot(node_id)
        cleaned = [str(ep).strip() for ep in direct_endpoints if str(ep).strip()]
        cleaned_p2p = [str(a).strip() for a in (p2p_addrs or ()) if str(a).strip()]
        pid = str(peer_id or "").strip()
        with self._lock:
            slot.last_seen = time.monotonic()
            if observed_ip:
                slot.observed_ip = str(observed_ip).strip()
            if cleaned:
                slot.direct_endpoints = cleaned
            if role in ("writer", "seeder"):
                slot.role = role
            if pid:
                slot.peer_id = pid
            if cleaned_p2p:
                slot.p2p_addrs = cleaned_p2p
        if pid:
            self.allow_peer_id(pid, node_id=node_id, role=role, addrs=cleaned_p2p)
        return self.get_ice_candidates(node_id)


def announce_ice_peer(
    base_url: str,
    node_id: str,
    direct_endpoints: Sequence[str],
    role: str = "seeder",
    token: str = "",
    timeout: float = 1.5,
    peer_id: str = "",
    p2p_addrs: Sequence[str] = (),
) -> bool:
    """root dfssvc の ``/_ice/announce`` へ読み取り用エンドポイントを登録する。"""
    import urllib.request

    root = str(base_url or "").strip().rstrip("/")
    cleaned_eps = [str(ep).strip() for ep in direct_endpoints if str(ep).strip()]
    cleaned_p2p = [str(a).strip() for a in p2p_addrs if str(a).strip()]
    pid = str(peer_id or "").strip()
    if not root or (not cleaned_eps and not pid):
        return False
    body_obj: Dict[str, Any] = {
        "node_id": node_id,
        "direct_endpoints": cleaned_eps,
        "role": role,
    }
    if pid:
        body_obj["peer_id"] = pid
    if cleaned_p2p:
        body_obj["p2p_addrs"] = cleaned_p2p
    payload = json.dumps(body_obj).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    resolved_token = str(token or os.environ.get("DFS_RELAY_TOKEN", "") or "").strip()
    if resolved_token:
        headers["X-DFS-Relay-Token"] = resolved_token
    req = urllib.request.Request(f"{root}/_ice/announce", data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=float(timeout)) as resp:
            return resp.status == 200
    except Exception:
        return False


def register_p2p_peer(
    base_url: str,
    peer_id: str,
    *,
    node_id: str = "",
    p2p_addrs: Sequence[str] = (),
    role: str = "seeder",
    sync_id: str = "",
    sub_path: str = "",
    token: str = "",
    timeout: float = 1.5,
) -> Dict[str, Any]:
    """root/domain dfssvc の ``/_p2p/peers`` へ自身の PeerID を自動登録し、許可リストを受け取る。"""
    import urllib.request

    root = str(base_url or "").strip().rstrip("/")
    pid = str(peer_id or "").strip()
    if not root or not pid:
        return {}
    payload_obj: Dict[str, Any] = {
        "peer_id": pid,
        "node_id": node_id,
        "p2p_addrs": [str(a).strip() for a in p2p_addrs if str(a).strip()],
        "role": role,
    }
    if sync_id:
        payload_obj["sync_id"] = str(sync_id).strip()
    if sub_path:
        payload_obj["sub_path"] = str(sub_path).strip()
    payload = json.dumps(payload_obj).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    resolved_token = str(token or os.environ.get("DFS_RELAY_TOKEN", "") or "").strip()
    if resolved_token:
        headers["X-DFS-Relay-Token"] = resolved_token
    req = urllib.request.Request(f"{root}/_p2p/peers", data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=float(timeout)) as resp:
            if resp.status != 200:
                return {}
            data = json.loads(resp.read().decode("utf-8"))
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def fetch_p2p_peers(
    base_url: str,
    *,
    token: str = "",
    timeout: float = 1.5,
) -> Dict[str, Any]:
    """root/domain dfssvc の ``/_p2p/peers`` から許可済み PeerID リストを取得する。"""
    import urllib.request

    root = str(base_url or "").strip().rstrip("/")
    if not root:
        return {}
    headers: Dict[str, str] = {}
    resolved_token = str(token or os.environ.get("DFS_RELAY_TOKEN", "") or "").strip()
    if resolved_token:
        headers["X-DFS-Relay-Token"] = resolved_token
    req = urllib.request.Request(f"{root}/_p2p/peers", headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=float(timeout)) as resp:
            if resp.status != 200:
                return {}
            data = json.loads(resp.read().decode("utf-8"))
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def discover_ice_candidates(
    base_url: str,
    node_id: Optional[str] = None,
    timeout: float = 1.5,
    token: str = "",
) -> List[Dict[str, Any]]:
    """root dfssvc の ``/_ice/candidates`` から到達候補一覧を取得する。"""
    import urllib.request

    root = str(base_url or "").strip().rstrip("/")
    if not root:
        return []
    url = f"{root}/_ice/candidates"
    if node_id:
        url = f"{url}?{urlencode({'node': node_id})}"
    headers: Dict[str, str] = {}
    resolved_token = str(token or os.environ.get("DFS_RELAY_TOKEN", "") or "").strip()
    if resolved_token:
        headers["X-DFS-Relay-Token"] = resolved_token
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=float(timeout)) as resp:
            if resp.status != 200:
                return []
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return []
    raw_cands = data.get("candidates")
    if not isinstance(raw_cands, list):
        return []
    result: List[Dict[str, Any]] = []
    for cand in raw_cands:
        if isinstance(cand, dict) and cand.get("endpoint"):
            result.append(dict(cand))
    return result


class RelayAgent:
    """NAT/FW 裏の dfssvc が root リレーへアウトバウンド接続し続けるエージェント。"""

    def __init__(
        self,
        relay_url: str,
        node_id: str,
        local_port: int,
        token: str = "",
        workers: int = 4,
        local_host: str = "127.0.0.1",
        pull_timeout: float = 35.0,
        direct_endpoints: Sequence[str] = (),
    ) -> None:
        self.relay_url = str(relay_url).strip().rstrip("/")
        parts = urlsplit(self.relay_url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(f"Invalid relay URL: {relay_url!r}")
        self.scheme = parts.scheme
        self.relay_host = parts.hostname
        self.relay_port = parts.port or (443 if self.scheme == "https" else 80)
        self.base_path = parts.path.rstrip("/")
        self.node_id = validate_node_id(node_id)
        self.local_host = local_host
        self.local_port = int(local_port)
        self.token = str(token or "")
        self.workers = max(1, int(workers))
        self.pull_timeout = float(pull_timeout)
        self.direct_endpoints = [
            str(ep).strip() for ep in direct_endpoints if str(ep).strip()
        ]

        self._running = False
        self._threads: List[threading.Thread] = []

    def _open_relay_conn(self, timeout: float) -> http.client.HTTPConnection:
        if self.scheme == "https":
            return http.client.HTTPSConnection(self.relay_host, self.relay_port, timeout=timeout)
        return http.client.HTTPConnection(self.relay_host, self.relay_port, timeout=timeout)

    def _forward_local(
        self,
        method: str,
        path: str,
        content_type: str,
        body: bytes,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, str, bytes]:
        conn = http.client.HTTPConnection(self.local_host, self.local_port, timeout=30.0)
        try:
            headers = {
                "Content-Type": content_type or "application/octet-stream",
                "Content-Length": str(len(body)),
                "Connection": "close",
            }
            if extra_headers:
                for k, v in extra_headers.items():
                    if k.lower() in ("x-dfs-ost-auth",) and v:
                        headers[k] = str(v)
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            resp_body = resp.read()
            resp_ct = resp.getheader("Content-Type") or "application/octet-stream"
            return resp.status, resp_ct, resp_body
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _worker_loop(self, worker_idx: int) -> None:
        wait_s = max(0.5, min(25.0, self.pull_timeout - 2.0)) if self.pull_timeout > 2.0 else 0.5
        pull_params = {"node": self.node_id, "wait": f"{wait_s:.1f}"}
        pull_path = f"{self.base_path}/_relay/pull?{urlencode(pull_params)}"
        base_headers: Dict[str, str] = {"Content-Length": "0", "Connection": "keep-alive"}
        if self.token:
            base_headers["X-DFS-Relay-Token"] = self.token
        if self.direct_endpoints:
            base_headers["X-DFS-Direct-Endpoints"] = ",".join(self.direct_endpoints)

        relay_conn: Optional[http.client.HTTPConnection] = None
        while self._running:
            try:
                if relay_conn is None:
                    relay_conn = self._open_relay_conn(max(self.pull_timeout, 30.0))
                relay_conn.request("POST", pull_path, body=b"", headers=base_headers)
                resp = relay_conn.getresponse()
                raw = resp.read()
                if resp.status == 204:
                    continue
                if resp.status in (401, 403):
                    print(
                        f"[dfs relay] auth rejected by {self.relay_url} ({resp.status})",
                        file=sys.stderr,
                    )
                    time.sleep(5.0)
                    continue
                if resp.status != 200:
                    time.sleep(1.0)
                    continue

                header, req_body = decode_relay_frame(raw)
                req_id = str(header["id"])
                method = str(header.get("method", "POST"))
                sub_path = str(header.get("path", "/"))
                req_ct = str(header.get("content_type", "application/octet-stream"))
                req_headers = header.get("headers") if isinstance(header.get("headers"), dict) else None

                try:
                    status, resp_ct, resp_body = self._forward_local(
                        method, sub_path, req_ct, req_body, extra_headers=req_headers
                    )
                except Exception as e:
                    status = 502
                    resp_ct = "application/json"
                    resp_body = json.dumps(
                        {"error_type": "ServiceUnavailableError", "message": str(e)}
                    ).encode("utf-8")

                reply_frame = encode_relay_frame(
                    {"status": status, "content_type": resp_ct},
                    resp_body,
                )
                reply_path = (
                    f"{self.base_path}/_relay/reply?"
                    f"{urlencode({'node': self.node_id, 'id': req_id})}"
                )
                reply_headers = {
                    "Content-Type": "application/octet-stream",
                    "Content-Length": str(len(reply_frame)),
                    "Connection": "keep-alive",
                }
                if self.token:
                    reply_headers["X-DFS-Relay-Token"] = self.token
                relay_conn.request("POST", reply_path, body=reply_frame, headers=reply_headers)
                reply_resp = relay_conn.getresponse()
                reply_resp.read()
            except (
                OSError,
                TimeoutError,
                ssl.SSLError,
                http.client.HTTPException,
                RelayError,
                KeyError,
            ):
                if relay_conn is not None:
                    try:
                        relay_conn.close()
                    except Exception:
                        pass
                    relay_conn = None
                if self._running:
                    time.sleep(0.5)
        if relay_conn is not None:
            try:
                relay_conn.close()
            except Exception:
                pass

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._threads = []
        for idx in range(self.workers):
            t = threading.Thread(
                target=self._worker_loop,
                args=(idx,),
                name=f"dfs-relay-{self.node_id}-{idx}",
                daemon=True,
            )
            t.start()
            self._threads.append(t)

    def close(self) -> None:
        self._running = False
