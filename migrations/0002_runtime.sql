CREATE TABLE IF NOT EXISTS talkgroups (
  id bigserial PRIMARY KEY,
  talkgroup integer NOT NULL UNIQUE CHECK (talkgroup BETWEEN 1 AND 16777215),
  name text,
  description text,
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS hotspot_listeners (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  enabled boolean NOT NULL DEFAULT true,
  mode text NOT NULL CHECK (mode IN ('simplex','duplex')),
  bind_ip inet NOT NULL DEFAULT '0.0.0.0',
  port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
  default_passphrase text,
  max_sessions integer NOT NULL DEFAULT 1000,
  session_timeout_seconds integer NOT NULL DEFAULT 60,
  allow_ids bigint[],
  deny_ids bigint[] NOT NULL DEFAULT '{}',
  per_id_passwords jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS hotspot_sessions (
  id bigserial PRIMARY KEY,
  listener_id uuid REFERENCES hotspot_listeners(id) ON DELETE CASCADE,
  repeater_id bigint NOT NULL,
  remote_addr text NOT NULL,
  connected_at timestamptz NOT NULL DEFAULT now(),
  last_seen timestamptz NOT NULL DEFAULT now(),
  disconnected_at timestamptz
);
CREATE INDEX IF NOT EXISTS hotspot_sessions_active_idx ON hotspot_sessions(listener_id,repeater_id) WHERE disconnected_at IS NULL;

CREATE TABLE IF NOT EXISTS ipsc_networks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  endpoint_id uuid NOT NULL UNIQUE REFERENCES endpoints(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('master','peer')),
  radio_id bigint NOT NULL,
  local_port integer NOT NULL CHECK (local_port BETWEEN 1 AND 65535),
  master_host text,
  master_port integer,
  alive_interval_seconds integer NOT NULL DEFAULT 5,
  jitter_buffer_depth integer NOT NULL DEFAULT 2,
  auth_enabled boolean NOT NULL DEFAULT false,
  auth_key text,
  max_peers integer NOT NULL DEFAULT 14
);

CREATE TABLE IF NOT EXISTS routing_rules (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  enabled boolean NOT NULL DEFAULT true,
  priority integer NOT NULL DEFAULT 100,
  match jsonb NOT NULL DEFAULT '{}'::jsonb,
  action jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS auth_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash bytea NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_sessions_expiry_idx ON auth_sessions(expires_at);

CREATE TABLE IF NOT EXISTS call_history (
  id bigserial PRIMARY KEY,
  endpoint text NOT NULL,
  source_id integer NOT NULL,
  destination_id integer NOT NULL,
  timeslot smallint NOT NULL CHECK (timeslot IN (1,2)),
  call_type text NOT NULL CHECK (call_type IN ('group','private')),
  stream_id bigint NOT NULL,
  event text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS call_history_created_idx ON call_history(created_at DESC);
CREATE INDEX IF NOT EXISTS call_history_stream_idx ON call_history(stream_id,created_at DESC);

CREATE TABLE IF NOT EXISTS system_settings (
  key text PRIMARY KEY,
  value jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
