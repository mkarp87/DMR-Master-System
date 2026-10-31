CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS endpoints (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  enabled boolean NOT NULL DEFAULT true,
  protocol text NOT NULL CHECK (protocol IN ('homebrew','openbridge','ipsc')),
  role text NOT NULL,
  kind text NOT NULL,
  config jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS bridges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS bridge_members (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  bridge_id uuid NOT NULL REFERENCES bridges(id) ON DELETE CASCADE,
  endpoint_id uuid NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
  timeslot smallint NOT NULL CHECK (timeslot IN (1,2)),
  talkgroup integer NOT NULL CHECK (talkgroup BETWEEN 1 AND 16777215),
  initially_active boolean NOT NULL DEFAULT true,
  timeout_seconds integer NOT NULL DEFAULT 0,
  timeout_policy text NOT NULL DEFAULT 'none' CHECK (timeout_policy IN ('none','on','off')),
  on_talkgroups integer[] NOT NULL DEFAULT '{}',
  off_talkgroups integer[] NOT NULL DEFAULT '{}',
  reset_talkgroups integer[] NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS bridge_member_route_idx ON bridge_members(endpoint_id,timeslot,talkgroup);

CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  role text NOT NULL DEFAULT 'administrator',
  enabled boolean NOT NULL DEFAULT true,
  totp_secret_encrypted bytea,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS service_settings (
  service text PRIMARY KEY CHECK (service IN ('weather','broadcastify','echolink','live_listen')),
  enabled boolean NOT NULL DEFAULT false,
  config jsonb NOT NULL DEFAULT '{}'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO service_settings(service,enabled) VALUES
 ('weather',false),('broadcastify',false),('echolink',false),('live_listen',false)
ON CONFLICT (service) DO NOTHING;

CREATE TABLE IF NOT EXISTS audit_log (
  id bigserial PRIMARY KEY,
  user_id uuid REFERENCES users(id),
  action text NOT NULL,
  object_type text NOT NULL,
  object_id text,
  before_state jsonb,
  after_state jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
