# Contributing

> **English** | [日本語](CONTRIBUTING.ja.md)

Bug reports, reproduction steps, documentation fixes, additional tests, and small backward-compatible fixes are welcome.

## Getting Started

- Do not report security issues in public issues; send them to the contact address in [SECURITY.md](SECURITY.md).
- For major design, protocol, or cryptographic changes, please open an issue first to share the goal and compatibility plan before implementing.
- For small bug fixes or documentation updates, feel free to submit a Pull Request directly.

## Development Environment

Python 3.11 or later and `uv` are used.

```bash
uv sync --extra test
uv run --extra test pytest -q
```

Depending on your changes, please also check macOS-, Linux-, and Windows-specific behavior.

## Pull Request Requirements

- Do not break existing tests
- Add a regression test for bug fixes
- If changing cryptography, signatures, delegation, logs, or archive formats, explain compatibility and migration paths
- Never commit private keys, `tree_secret`, or real user configuration files
- Ensure any published logs or fixtures use synthetic data or reserved example domains/IPs
- Verify that generated artifacts and dependency updates are limited to the intended scope

When multiple implementation approaches exist and user-facing compatibility impact is significant, discuss the design before writing code.

## License

Contributions are provided under the [MIT License](LICENSE).
