# Security Policy

> **English** | [日本語](SECURITY.ja.md)

## Supported Versions

In principle, security fixes apply only to the latest release series.
Currently, `0.1.x` is treated as the initial release series.

## Reporting a Vulnerability

Please do not disclose security issues in public issues. Report them
privately to the following address:

**yashiki2005@gmail.com**

If possible, please include the following information:

- Affected version(s) and environment
- Type of issue and expected impact
- Reproduction steps or minimal proof-of-concept code
- Known mitigations
- Contact information that may be shared publicly

Do not send `tree_secret`, private keys, or real user data.
If needed for verification, please reproduce using disposable keys and synthetic data.

## Response Policy

We aim to acknowledge receipt within 7 days. Fix and disclosure timelines
will be coordinated after confirming impact and reproducibility. Please refrain
from publicly disclosing unpatched vulnerabilities in advance.

## Scope

In scope are cryptographic operations, signature and delegation verification,
path boundaries, archive extraction, Web UI authentication, relay authorization,
and handling of remote inputs.

This project has not undergone an independent security audit. Before deploying
in production, please review the threat model yourself and conduct an external
review as needed.
