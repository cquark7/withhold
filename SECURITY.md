# Security policy

withhold scans supported outgoing request bodies locally to reduce accidental
disclosure. Its [behavior contract](CONTRACTS.md) describes inspected surfaces,
passthrough traffic, and the local HTTPS inspection CA.

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/cquark7/withhold/security/advisories/new).
If that option is unavailable, open a public issue requesting a private contact
**without describing the vulnerability**.

Include the version or commit, OS/CPU, affected editor/provider, expected and
observed behavior, likely impact, and reproduction steps using synthetic data.
Do not attach credentials, CA keys, session records, settings backups, finding
logs, or captured requests. Keep exploit details private until disclosure is
coordinated.

Security fixes are developed on `main`. Include your version or commit so the
affected behavior can be reproduced.

## Recover local access

Run `withhold off` with the same `WITHHOLD_DIR` to restore managed settings. Restart
VS Code normally if you used `withhold launch`. Preserve local state until
settings restoration and CA trust removal are verified. See
[recovery and removal](docs/usage.md#recovery-and-removal).
