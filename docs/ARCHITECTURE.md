# Architecture decisions — v0.1

## Data plane

The critical forwarding path is Rust/Tokio and must not depend on PostgreSQL, the dashboard, audio decoding, or external services.

Adapters normalize protocol-specific packets to a common DMR representation. The router keys routes by `(ingress endpoint, timeslot, talkgroup)` and resolves precompiled egress targets in memory.

## Protocol adapters

- Homebrew/MMDVM: server and outbound roles; dedicated repeaters and dynamic hotspot sessions.
- OpenBridge: peer links to HBlink3/external networks.
- IPSC: MASTER or PEER role. Hardware/platform (XPR8400, cBridge, other) is metadata, not a role.

## Control plane

PostgreSQL stores endpoints, bridges, rule state, users, service configuration and audit history. A future config service validates writes, builds a new route table, and atomically replaces the active table without restarting sessions.

## Optional services

Weather, Broadcastify, EchoLink and Live Listen exist in the schema from v0.1 but default disabled. They must consume bounded event/media streams so failure or backpressure cannot stop DMR forwarding.

## Migration

Both legacy and current HBlink3 names are accepted. Legacy `rules.py` files can be bridge-centric and contain per-member timeslot/talkgroup mappings, dynamic activation/deactivation talkgroups, timers and service endpoints. Migration preserves those semantics before any UI-level simplification.
