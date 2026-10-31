# Architecture

## Data plane

Protocol adapters normalize traffic into the common DMR representation used by the router. Homebrew and OpenBridge use DMRD directly. IPSC Group Voice is converted to/from DMRD at the IPSC boundary.

The router owns bridge runtime state and performs:

- `(endpoint, timeslot, talkgroup)` bridge lookup
- TG and timeslot translation
- ON/OFF/RESET bridge activation
- timeout policy processing
- duplicate suppression
- stream start/end tracking
- learned subscriber-location routing for private calls

When a group route changes a talkgroup or timeslot, DMR Link Control is regenerated rather than only changing the outer DMRD header. Voice headers, terminators and embedded LC therefore remain consistent with the translated destination.

## Homebrew/MMDVM

Server mode supports Homebrew login challenge/response, configuration, ping/pong, disconnect, authenticated DMRD ingress, session expiration, per-radio passwords, and allow/deny policy. A shared listener can hold many dynamic clients, avoiding the old hotspot-proxy backend-port pool model.

Outbound mode implements the Homebrew client handshake and can peer with an existing HBlink-compatible server during migration.

## OpenBridge

OpenBridge validates HMAC-SHA1, optional remote network ID and expected peer address. Frames enter the same router as Homebrew traffic.

## IPSC

IPSC configuration separates protocol role from hardware platform. `Master` and `Peer` are roles; XPR8400, cBridge and other devices are deployment metadata.

Implemented pre-live:

- master/peer registration and deregistration
- peer list exchange and full-mesh registration
- alive/keepalive handling
- optional 10-byte HMAC-SHA1 authentication
- peer expiry
- Group Voice packet parsing/building
- AMBE burst conversion between IPSC and DMRD layout
- voice header/terminator and embedded LC reconstruction
- 60 ms egress pacing

Private voice and data are not forwarded until real device captures validate their framing.

## Control plane

PostgreSQL stores endpoints, talkgroups, bridges, bridge members, users, auth sessions, audit history, call history, hotspot/IPSC settings and system settings. The admin API validates writes. Bridge configuration can be reloaded into the in-memory route engine without restarting the process.

Transport socket topology currently starts at process launch, so adding/removing or materially changing endpoint listeners requires restart.

## HTTP surfaces

The public dashboard is read-only and exposes endpoint, bridge and recent-call status. The admin UI uses authenticated API calls for endpoints, talkgroups, bridges, calls and route reload.

## Future services

Live Listen, Broadcastify, EchoLink and weather services should consume bounded internal event/media streams. They must remain isolated from forwarding so media-service failure cannot stop DMR routing.
