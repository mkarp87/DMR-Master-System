# DMR Master System

A modular DMR network platform for Homebrew/MMDVM, OpenBridge and Motorola IPSC systems.

## Status

Early v0.1 development. The current tree establishes:

- typed common DMR frame/endpoint model
- legacy + current HBlink mode normalization (`MASTER/SERVER`, `PEER/OUTBOUND`)
- HBP `DMRD` packet parse/encode foundation
- OpenBridge media codec wrapper
- IPSC role/state/jitter timing foundation
- compiled in-memory routing table with TG/TS translation
- legacy `hblink.cfg` + `rules.py` import/validation utility
- PostgreSQL schema
- Docker multi-stage build/test image
- public health API skeleton

## Architecture

```
Homebrew/MMDVM ----\
Hotspots -----------+--> protocol adapters --> common DMR core --> compiled router
OpenBridge ---------+                                      |             |
IPSC Master/Peer ---/                                      |             +--> endpoints
                                                           +--> events/media (future)
```

The packet forwarding hot path is designed to be database-free. PostgreSQL is the control-plane source of truth; validated changes will compile into immutable in-memory route tables and swap atomically.

## Legacy migration check

```
python3 tools/import_legacy.py \
  --config fixtures/hblink.example.cfg \
  --rules fixtures/rules.example.py \
  --out fixtures/imported-network.example.json
```

The importer accepts both older HBlink3 naming and newer naming. It never silently discards unresolved bridge members; those are emitted under `validation.missing_system_references`.

## Build/test with Docker

```
docker build -t dmr-master-system:dev .
```

The build stage runs `cargo test --workspace` before producing the release binary.

## Development deployment

Copy `.env.example` to `.env`, change the PostgreSQL password, then:

```
docker compose up --build
```

Public health endpoint:

```
GET /api/public/health
```

## v0.1 compatibility targets

1. Homebrew/MMDVM server sessions
2. OpenBridge peer to existing HBlink3
3. IPSC MASTER and PEER roles (XPR8400/cBridge target)
4. HBlink conference-bridge behavior including TG/TS translation and dynamic ON/OFF/RESET rules
5. Native hotspot sessions plus legacy proxy compatibility mode
6. Public monitoring API; private administration added after routing compatibility

## License

GPL-3.0-only.
