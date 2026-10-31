# Implementation status

This document separates implemented software from live-interoperability claims.

## Implemented pre-live

### Homebrew/MMDVM
- Server challenge-response authentication.
- Configuration and keepalive lifecycle.
- Session timeout and disconnect handling.
- Authenticated DMRD ingress/egress.
- Shared listener with multiple peers.
- Per-ID passwords and allow/deny policy.
- Homebrew outbound/client mode.

### Routing
- Common DMR frame model.
- Conference bridge routing by endpoint, timeslot and talkgroup.
- TG/TS translation.
- Full and embedded Group Voice Link Control regeneration.
- Dynamic ON/OFF/RESET activation.
- Timeout policies.
- Duplicate suppression and call lifecycle tracking.
- Learned private-call subscriber locations for Homebrew/OpenBridge unit systems.

### OpenBridge
- HMAC-SHA1 framing validation/generation.
- Network-ID validation.
- Bidirectional DMRD routing.
- Same common router as Homebrew.

### IPSC
- Master and Peer roles.
- Registration/deregistration.
- Peer-list and full-mesh registration handling.
- Keepalives and peer expiry.
- Optional authentication trailer handling.
- Group Voice header/voice/terminator conversion to/from DMRD.
- AMBE bit-layout conversion and DMR LC reconstruction.
- 60 ms outbound media pacing.

IPSC Private Voice and IPSC Data are parsed enough to classify but intentionally not forwarded.

### PostgreSQL/control plane
- Endpoint configuration.
- Talkgroups.
- Bridges/members and dynamic rule fields.
- Users/password hashing/auth sessions.
- Audit log.
- Call history.
- Runtime/system service tables.
- Admin CRUD APIs and route reload.

### Web/deployment
- Public read-only status dashboard.
- Authenticated admin page/API.
- Docker image and Docker Compose with PostgreSQL.
- CI format/Clippy/test/build workflow.

## Requires live validation

- MMDVM interoperability with multiple firmware/hardware variants.
- OpenBridge interoperability with the production HBlink peer configuration.
- Exact TG/TS translation behavior against real RF calls.
- XPR8400 and cBridge IPSC registration/media behavior.
- IPSC authentication variants and vendor timing edge cases.
- NAT/rebinding behavior under real hotspot networks.
- Production load, packet loss, jitter and restart recovery.

## Not part of the pre-live core completion

These remain post-core features rather than blockers for the first network migration test:

- Live Listen / AMBE decoding to browser audio.
- Broadcastify streaming service.
- EchoLink integration.
- Weather service generation.
- TOTP MFA.
- Full React/TypeScript SPA replacement for the built-in admin UI.
