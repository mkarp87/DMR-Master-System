# DMR Master System

DMR Master System is a Rust/Tokio DMR networking platform designed as a modern migration path from HBlink-style deployments. It normalizes Homebrew/MMDVM, OpenBridge, and Motorola IPSC traffic into a common DMR frame model, routes traffic through an in-memory bridge engine, and stores control-plane configuration in PostgreSQL.

## Pre-live status

The current tree implements the software path intended for pre-live validation:

- Homebrew/MMDVM server authentication, session tracking, keepalives, per-ID passwords, allow/deny policy, NAT/source-port refresh, and many clients on one UDP listener.
- Homebrew outbound/client mode for migration peering.
- OpenBridge authenticated transport with network-ID validation and bidirectional routing.
- HBlink-style bridge members with timeslot/talkgroup mapping, ON/OFF/RESET activation talkgroups, and timeout policies.
- DMR group-voice TG/TS translation including Full Link Control and Embedded Link Control regeneration.
- Learned subscriber-location routing for private Homebrew/OpenBridge traffic.
- IPSC Master/Peer control plane, peer registry, keepalives, full-mesh peer discovery, HMAC handling, Group Voice media conversion, and 60 ms egress pacing.
- PostgreSQL endpoints, talkgroups, bridges, bridge members, users, sessions, audit log, call history, runtime settings, and migrations.
- Public live-status dashboard and authenticated admin UI/API.
- Docker Compose deployment with PostgreSQL.

IPSC interoperability is based on public reverse-engineered protocol implementations. Real XPR8400/cBridge captures remain required before calling IPSC production-compatible. IPSC private/data forwarding is intentionally not enabled pre-live.

## Architecture

```text
MMDVM / repeater / hotspot -- Homebrew --\
Homebrew peer ---------------------------+-- protocol adapters -- common DMRD -- router -- egress
OpenBridge ------------------------------+
Motorola IPSC Master/Peer ---------------/
                                               |
                                               +-- PostgreSQL control plane
                                               +-- public/admin HTTP API
```

The forwarding hot path does not query PostgreSQL per packet. Database configuration is loaded and compiled into in-memory routing state.

## Build validation

```bash
cargo fmt --all
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build --workspace --release
```

Docker validation:

```bash
docker build -t dmr-master-system:test .
```

## Development deployment

```bash
cp .env.example .env
# Change all default passwords in .env
docker compose up --build
```

Public dashboard: `http://SERVER:8080/`

Admin UI: `http://SERVER:8080/admin`

Health: `GET /api/public/health`

To use PostgreSQL as the endpoint/bridge source of truth, set `DMR_USE_DATABASE_CONFIG=true` after populating the database. Endpoint socket additions/removals currently require a process restart; bridge edits can be hot-reloaded from the admin API.

## Legacy import

```bash
python3 tools/import_legacy.py \
  --config fixtures/hblink.example.cfg \
  --rules fixtures/rules.example.py \
  --out fixtures/imported-network.example.json
```

The importer preserves unresolved bridge member references as validation warnings rather than silently discarding them.

## Before live traffic

Follow [docs/PRE_LIVE_TEST.md](docs/PRE_LIVE_TEST.md). The first live target should be a lab MMDVM/Homebrew endpoint through DMR Master to a dedicated OpenBridge peer on the existing HBlink system. IPSC should be tested separately after Homebrew/OpenBridge is stable.

## License

GPL-3.0-only.
