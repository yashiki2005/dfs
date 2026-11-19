# Changelog

> [English](CHANGELOG.md) | **日本語**

このファイルの形式は [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/) に従います。

## [Unreleased]

## [0.1.0] - 2026-11-15

初回公開リリース。

### Added

- 単一書き手の署名付き委譲、追記ログ、Merkleツリーを使う分散ファイルシステム
- `dfscli` による `copy`、`sync`、`pull`、`ls`、`cat`、`archive` などのCLI
- `dfssvc` によるL2名簿とL3チャンクストアのローカル運用
- ChaCha20-Poly1305によるチャンク暗号化、Zstandard圧縮、内容アドレス型の重複排除
- FUSE / macFUSE / FUSE-Tマウント
- DNSSEC・TOFUによるroot公開鍵の配布、検証済みロケータ、読み取り複製
- ICE、libp2p QUIC、Direct-firstリレーによるNAT越え
- 読み取り専用招待、出力専用一時鍵、Web UI
- PAR2付きarchive、BitTorrentメタデータ、`zstd:chunked` archive
- macOS、Linux、Windows向けのCIとリリースビルド

### Security

- Ed25519署名によるroot・委譲・ログ・archive descriptorの検証
- パストラバーサル、シンボリックリンク脱出、危険なarchive memberの拒否
- 新規リモート向けのバージョン付き`scrypt-v1` KDF
- KDF識別子を持たない既存リモート・招待・archiveの互換読み込み
- 委譲エポック切替中の履歴保持と複製検証
- Web UIのトークン認証、セッションCookie、試行回数制限

### Known limitations

- 独立した第三者セキュリティ監査は未実施
- 書き込みは単一ライターを前提とし、マルチマスター書き込みには対応しない
- 招待トークンは`tree_secret`を含むBearer資格情報として厳重に管理する必要がある
- 公開L2/L3を直接インターネットへ置く場合は、防火壁、レート制限、容量制限が必要

[Unreleased]: https://github.com/yashiki2005/dfs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yashiki2005/dfs/releases/tag/v0.1.0
