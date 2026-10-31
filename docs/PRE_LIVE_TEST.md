# Pre-live validation checklist

Do not connect production repeaters until all local/CI checks pass.

## 1. Source validation

```bash
cargo fmt --all
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build --workspace --release
docker build -t dmr-master-system:test .
```

## 2. Configuration safety

- Change PostgreSQL and admin passwords.
- Use a dedicated test Homebrew port and OpenBridge port.
- Do not reuse a production OpenBridge network ID until the lab path is verified.
- Start with one synthetic bridge and one test TG.
- Keep IPSC disabled for the first Homebrew/OpenBridge test.

## 3. First live path

Target:

```text
MMDVM -> Homebrew -> DMR Master -> OpenBridge -> existing HBlink3
MMDVM <- Homebrew <- DMR Master <- OpenBridge <- existing HBlink3
```

Validate in order:

1. MMDVM login challenge/response succeeds.
2. Ping/pong remains stable for at least several minutes.
3. A same-TG group call crosses in both directions.
4. Header, voice and terminator frames are observed.
5. TG translation works in both directions.
6. Timeslot translation works in both directions.
7. Dynamic ON/OFF/RESET TG behavior matches the imported bridge rule.
8. Session expiration/reconnect works.
9. Two simultaneous independent endpoints do not cross-route incorrectly.

Capture both sides with `tcpdump`/Wireshark during this phase.

## 4. Native hotspot test

Add multiple test MMDVM clients to the same listener. Validate per-ID passwords, allow/deny policy, source-port/NAT changes, disconnect/reconnect and independent stream state.

## 5. IPSC test

Use a dedicated lab IPSC network first.

1. Test DMR Master in Peer role against a known master.
2. Verify registration, peer list, full-mesh registration and keepalives.
3. Capture a Group Voice call from XPR8400/cBridge to DMR Master.
4. Compare packet framing, RTP sequence/timestamp progression and AMBE payload against the implementation.
5. Test DMR Master-originated Group Voice toward the IPSC network.
6. Only after packet-level comparison succeeds should IPSC be considered interoperable.

IPSC private/data traffic remains disabled until captures establish the exact supported framing.

## 6. Database/admin test

- Create/edit/delete endpoint records.
- Create/edit/delete talkgroups.
- Create/edit/delete bridges and members.
- Reload routes and verify bridge state changes without restart.
- Verify call history and audit records.
- Confirm unauthenticated admin calls return 401.

## 7. Production readiness gate

Before production migration, add operational monitoring, backup/restore for PostgreSQL, TLS/reverse proxy, credential rotation, rate limits, and a rollback plan to the existing HBlink deployment.
