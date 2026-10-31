# HTTP API

## Public

- `GET /api/public/health` - version, system count, compiled route count, database status.
- `GET /api/public/status` - endpoint state, bridge runtime state and recent calls.

## Authentication

- `POST /api/admin/login`

```json
{"username":"admin","password":"..."}
```

Returns a bearer token. Send it as `Authorization: Bearer TOKEN` to all admin routes.

## Admin endpoints

- `GET /api/admin/endpoints`
- `POST /api/admin/endpoints`
- `DELETE /api/admin/endpoints/{uuid}`

Endpoint body example:

```json
{"name":"DEMO-HBP","enabled":true,"protocol":"homebrew","role":"server","kind":"repeater","config":{"bind_ip":"0.0.0.0","port":62031,"passphrase":"change-me"}}
```

## Admin talkgroups

- `GET /api/admin/talkgroups`
- `POST /api/admin/talkgroups`
- `DELETE /api/admin/talkgroups/{id}`

## Admin bridges

- `GET /api/admin/bridges`
- `POST /api/admin/bridges`
- `DELETE /api/admin/bridges/{uuid}`
- `POST /api/admin/reload-routes`

Bridge member fields include endpoint, timeslot, talkgroup, initial state, timeout policy/seconds and ON/OFF/RESET talkgroup arrays.

## Calls

- `GET /api/admin/calls` - recent persisted call events.
