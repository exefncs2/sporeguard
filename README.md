# 🛡️ SporeGuard

**Ultra-lightweight local security anomaly radar powered by [SporeFlow](https://github.com/exefncs2/sporeflow) (`:9090`) & [SporeVault](https://github.com/exefncs2/sporevault) (`:8081`).**  
Single-file, zero-dependency Python 3 (`std` library only) · Monitor-only, zero system interference · Log normalization · 2-hour fingerprint cooldown · Exposed port watchdog · KDE/Linux desktop alerts.

[English](./README.md) | [繁體中文](./README.zh-TW.md) | [AI / Agent Index (`llms.txt`)](./llms.txt) | [🍄 SporeFlow](https://github.com/exefncs2/sporeflow) | [🍄 SporeVault](https://github.com/exefncs2/sporevault)

---

## Why Python Instead of Rust? (Intentional Engineering Trade-off)

Both [SporeFlow](https://github.com/exefncs2/sporeflow) and [SporeVault](https://github.com/exefncs2/sporevault) are 100% Pure Rust—so why is **SporeGuard** written in pure Python standard library?

1. **Right Tool for the Layer (Control Plane vs. Data Plane)**:
   - SporeFlow & SporeVault sit on the **hot data path** (memory-aligned zero-copy scanning, `mprotect(PROT_READ)`, sub-millisecond `:9090` binary sockets) where Rust shines.
   - SporeGuard is a **one-shot control-plane glue script** (`Type=oneshot`, wakes up once per hour for ~0.1s) that shells out to `journalctl`, `ss`, `notify-send`, and `systemctl`, then offloads vector baseline matching to Rust via SporeVault/SporeFlow. Rewriting hourly shell-orchestration in Rust adds build friction with zero meaningful runtime gain.
2. **Instant Auditability & Live Rule Editing (Crucial for Security Ops)**:
   - Security administrators prefer **transparent, readable plain-text rules** over opaque compiled binaries for host monitoring.
   - Because `spore-guard.py` is a single ~400-line file using **zero `pip` packages**, anyone can inspect every regex (`HIGH_RISK_PATTERNS`), tweak port allowlists (`ALLOWED_EXPOSED_PORTS`), or adjust normalization rules and run immediately without recompiling.
3. **Zero Supply-Chain Bloat**:
   - No `requirements.txt`, no `virtualenv`, no third-party Python packages—runs directly on `/usr/bin/python3` shipped with Fedora / Bazzite / Ubuntu / Debian.

---

## Features

- **`--learn`**: Extracts deduplicated, normalized system log patterns from the past 24 hours (`journalctl`) and stores them in SporeVault's `security-baseline` cluster (excluding high-risk signals).
- **`--scan`**: Scans recent errors (`err..emerg`) and non-loopback exposed listening ports (`ss -tulnH`), queries SporeFlow/SporeVault for baseline similarity, writes anomalies into the `security-alert` cluster (`#security-alert`), and sends desktop notifications (`notify-send`).
- **Anti-Spam Protection**: 2-hour SHA-256 fingerprint cooldown (`~/.local/state/spore-guard/state.json`) + max 5 alerts per scan.
- **`--set-interval <MINUTES>`**: Generates and reloads `systemd --user` timer (`spore-guard.timer`) automatically.

---

## Quick Start

```bash
# 1. Install to ~/.local/bin
install -m 755 spore-guard.py ~/.local/bin/spore-guard.py

# 2. Learn 24-hour normal baseline (requires SporeFlow + SporeVault running locally)
spore-guard.py --learn

# 3. Run a manual scan or test desktop notification
spore-guard.py --scan
spore-guard.py --test-alert

# 4. Enable hourly automatic scanning via systemd --user timer
spore-guard.py --set-interval 60
```

Licensed under the MIT License (`SPDX-License-Identifier: MIT`).
