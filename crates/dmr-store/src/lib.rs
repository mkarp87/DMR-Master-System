use anyhow::{anyhow, Context, Result};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone)]
pub struct Store {
    pool: PgPool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointRecord {
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub protocol: String,
    pub role: String,
    pub kind: String,
    pub config: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewEndpoint {
    pub name: String,
    pub enabled: bool,
    pub protocol: String,
    pub role: String,
    pub kind: String,
    #[serde(default)]
    pub config: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeMemberRecord {
    pub endpoint: String,
    pub timeslot: i16,
    pub talkgroup: i32,
    pub initially_active: bool,
    pub timeout_seconds: i32,
    pub timeout_policy: String,
    pub on_talkgroups: Vec<i32>,
    pub off_talkgroups: Vec<i32>,
    pub reset_talkgroups: Vec<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeRecord {
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub members: Vec<BridgeMemberRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TalkgroupRecord {
    pub id: i64,
    pub talkgroup: i32,
    pub name: Option<String>,
    pub description: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewTalkgroup {
    pub talkgroup: i32,
    pub name: Option<String>,
    pub description: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewBridge {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub members: Vec<BridgeMemberRecord>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallRecord {
    pub endpoint: String,
    pub source_id: i32,
    pub destination_id: i32,
    pub timeslot: i16,
    pub call_type: String,
    pub stream_id: i64,
    pub event: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserIdentity {
    pub id: Uuid,
    pub username: String,
    pub role: String,
}

impl Store {
    pub async fn connect(database_url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .acquire_timeout(Duration::from_secs(5))
            .connect(database_url)
            .await
            .context("connect PostgreSQL")?;
        sqlx::raw_sql(include_str!("../../../migrations/0001_initial.sql"))
            .execute(&pool)
            .await
            .context("apply initial database schema")?;
        sqlx::raw_sql(include_str!("../../../migrations/0002_runtime.sql"))
            .execute(&pool)
            .await
            .context("apply runtime database schema")?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn health(&self) -> bool {
        sqlx::query("SELECT 1").execute(&self.pool).await.is_ok()
    }

    pub async fn list_endpoints(&self) -> Result<Vec<EndpointRecord>> {
        let rows = sqlx::query(
            "SELECT id,name,enabled,protocol,role,kind,config FROM endpoints ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| EndpointRecord {
                id: row.get("id"),
                name: row.get("name"),
                enabled: row.get("enabled"),
                protocol: row.get("protocol"),
                role: row.get("role"),
                kind: row.get("kind"),
                config: row.get("config"),
            })
            .collect())
    }

    pub async fn upsert_endpoint(&self, endpoint: &NewEndpoint) -> Result<EndpointRecord> {
        let row = sqlx::query(
            r#"INSERT INTO endpoints(name,enabled,protocol,role,kind,config)
               VALUES($1,$2,$3,$4,$5,$6)
               ON CONFLICT(name) DO UPDATE SET enabled=EXCLUDED.enabled,protocol=EXCLUDED.protocol,
                 role=EXCLUDED.role,kind=EXCLUDED.kind,config=EXCLUDED.config,updated_at=now()
               RETURNING id,name,enabled,protocol,role,kind,config"#,
        )
        .bind(&endpoint.name)
        .bind(endpoint.enabled)
        .bind(&endpoint.protocol)
        .bind(&endpoint.role)
        .bind(&endpoint.kind)
        .bind(&endpoint.config)
        .fetch_one(&self.pool)
        .await?;
        Ok(EndpointRecord {
            id: row.get("id"),
            name: row.get("name"),
            enabled: row.get("enabled"),
            protocol: row.get("protocol"),
            role: row.get("role"),
            kind: row.get("kind"),
            config: row.get("config"),
        })
    }

    pub async fn delete_endpoint(&self, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM endpoints WHERE id=$1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_bridges(&self) -> Result<Vec<BridgeRecord>> {
        let bridges = sqlx::query("SELECT id,name,enabled FROM bridges ORDER BY name")
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::new();
        for bridge in bridges {
            let id: Uuid = bridge.get("id");
            let members = sqlx::query(
                r#"SELECT e.name endpoint,bm.timeslot,bm.talkgroup,bm.initially_active,
                   bm.timeout_seconds,bm.timeout_policy,bm.on_talkgroups,bm.off_talkgroups,bm.reset_talkgroups
                   FROM bridge_members bm JOIN endpoints e ON e.id=bm.endpoint_id
                   WHERE bm.bridge_id=$1 ORDER BY e.name,bm.timeslot,bm.talkgroup"#,
            )
            .bind(id)
            .fetch_all(&self.pool)
            .await?;
            out.push(BridgeRecord {
                id,
                name: bridge.get("name"),
                enabled: bridge.get("enabled"),
                members: members
                    .into_iter()
                    .map(|row| BridgeMemberRecord {
                        endpoint: row.get("endpoint"),
                        timeslot: row.get("timeslot"),
                        talkgroup: row.get("talkgroup"),
                        initially_active: row.get("initially_active"),
                        timeout_seconds: row.get("timeout_seconds"),
                        timeout_policy: row.get("timeout_policy"),
                        on_talkgroups: row.get("on_talkgroups"),
                        off_talkgroups: row.get("off_talkgroups"),
                        reset_talkgroups: row.get("reset_talkgroups"),
                    })
                    .collect(),
            });
        }
        Ok(out)
    }

    pub async fn list_talkgroups(&self) -> Result<Vec<TalkgroupRecord>> {
        let rows = sqlx::query(
            "SELECT id,talkgroup,name,description,enabled FROM talkgroups ORDER BY talkgroup",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| TalkgroupRecord {
                id: row.get("id"),
                talkgroup: row.get("talkgroup"),
                name: row.get("name"),
                description: row.get("description"),
                enabled: row.get("enabled"),
            })
            .collect())
    }

    pub async fn upsert_talkgroup(&self, item: &NewTalkgroup) -> Result<TalkgroupRecord> {
        if !(1..=16_777_215).contains(&item.talkgroup) {
            return Err(anyhow!("talkgroup must be between 1 and 16777215"));
        }
        let row = sqlx::query(
            r#"INSERT INTO talkgroups(talkgroup,name,description,enabled)
               VALUES($1,$2,$3,$4)
               ON CONFLICT(talkgroup) DO UPDATE SET name=EXCLUDED.name,description=EXCLUDED.description,
                 enabled=EXCLUDED.enabled,updated_at=now()
               RETURNING id,talkgroup,name,description,enabled"#,
        )
        .bind(item.talkgroup)
        .bind(&item.name)
        .bind(&item.description)
        .bind(item.enabled)
        .fetch_one(&self.pool)
        .await?;
        Ok(TalkgroupRecord {
            id: row.get("id"),
            talkgroup: row.get("talkgroup"),
            name: row.get("name"),
            description: row.get("description"),
            enabled: row.get("enabled"),
        })
    }

    pub async fn delete_talkgroup(&self, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM talkgroups WHERE id=$1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn upsert_bridge(&self, bridge: &NewBridge) -> Result<BridgeRecord> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            r#"INSERT INTO bridges(name,enabled) VALUES($1,$2)
               ON CONFLICT(name) DO UPDATE SET enabled=EXCLUDED.enabled,updated_at=now()
               RETURNING id"#,
        )
        .bind(&bridge.name)
        .bind(bridge.enabled)
        .fetch_one(&mut *tx)
        .await?;
        let bridge_id: Uuid = row.get("id");

        sqlx::query("DELETE FROM bridge_members WHERE bridge_id=$1")
            .bind(bridge_id)
            .execute(&mut *tx)
            .await?;

        for member in &bridge.members {
            if !matches!(member.timeslot, 1 | 2) {
                return Err(anyhow!(
                    "bridge member {} has invalid timeslot {}",
                    member.endpoint,
                    member.timeslot
                ));
            }
            if !(1..=16_777_215).contains(&member.talkgroup) {
                return Err(anyhow!(
                    "bridge member {} has invalid talkgroup {}",
                    member.endpoint,
                    member.talkgroup
                ));
            }
            let endpoint_id: Uuid = sqlx::query_scalar("SELECT id FROM endpoints WHERE name=$1")
                .bind(&member.endpoint)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| anyhow!("unknown endpoint {}", member.endpoint))?;
            sqlx::query(
                r#"INSERT INTO bridge_members(
                     bridge_id,endpoint_id,timeslot,talkgroup,initially_active,timeout_seconds,
                     timeout_policy,on_talkgroups,off_talkgroups,reset_talkgroups)
                   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"#,
            )
            .bind(bridge_id)
            .bind(endpoint_id)
            .bind(member.timeslot)
            .bind(member.talkgroup)
            .bind(member.initially_active)
            .bind(member.timeout_seconds.max(0))
            .bind(member.timeout_policy.to_ascii_lowercase())
            .bind(&member.on_talkgroups)
            .bind(&member.off_talkgroups)
            .bind(&member.reset_talkgroups)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        self.bridge_by_id(bridge_id).await
    }

    async fn bridge_by_id(&self, id: Uuid) -> Result<BridgeRecord> {
        let bridge = sqlx::query("SELECT id,name,enabled FROM bridges WHERE id=$1")
            .bind(id)
            .fetch_one(&self.pool)
            .await?;
        let members = sqlx::query(
            r#"SELECT e.name endpoint,bm.timeslot,bm.talkgroup,bm.initially_active,
               bm.timeout_seconds,bm.timeout_policy,bm.on_talkgroups,bm.off_talkgroups,bm.reset_talkgroups
               FROM bridge_members bm JOIN endpoints e ON e.id=bm.endpoint_id
               WHERE bm.bridge_id=$1 ORDER BY e.name,bm.timeslot,bm.talkgroup"#,
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await?;
        Ok(BridgeRecord {
            id: bridge.get("id"),
            name: bridge.get("name"),
            enabled: bridge.get("enabled"),
            members: members
                .into_iter()
                .map(|row| BridgeMemberRecord {
                    endpoint: row.get("endpoint"),
                    timeslot: row.get("timeslot"),
                    talkgroup: row.get("talkgroup"),
                    initially_active: row.get("initially_active"),
                    timeout_seconds: row.get("timeout_seconds"),
                    timeout_policy: row.get("timeout_policy"),
                    on_talkgroups: row.get("on_talkgroups"),
                    off_talkgroups: row.get("off_talkgroups"),
                    reset_talkgroups: row.get("reset_talkgroups"),
                })
                .collect(),
        })
    }

    pub async fn delete_bridge(&self, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM bridges WHERE id=$1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn record_call(&self, call: &CallRecord) -> Result<()> {
        sqlx::query(
            r#"INSERT INTO call_history(endpoint,source_id,destination_id,timeslot,call_type,stream_id,event)
               VALUES($1,$2,$3,$4,$5,$6,$7)"#,
        )
        .bind(&call.endpoint)
        .bind(call.source_id)
        .bind(call.destination_id)
        .bind(call.timeslot)
        .bind(&call.call_type)
        .bind(call.stream_id)
        .bind(&call.event)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn recent_calls(&self, limit: i64) -> Result<Vec<Value>> {
        let rows = sqlx::query(
            r#"SELECT endpoint,source_id,destination_id,timeslot,call_type,stream_id,event,created_at::text created_at
               FROM call_history ORDER BY id DESC LIMIT $1"#,
        )
        .bind(limit.clamp(1, 500))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                serde_json::json!({
                    "endpoint": row.get::<String,_>("endpoint"),
                    "source_id": row.get::<i32,_>("source_id"),
                    "destination_id": row.get::<i32,_>("destination_id"),
                    "timeslot": row.get::<i16,_>("timeslot"),
                    "call_type": row.get::<String,_>("call_type"),
                    "stream_id": row.get::<i64,_>("stream_id"),
                    "event": row.get::<String,_>("event"),
                    "created_at": row.get::<String,_>("created_at")
                })
            })
            .collect())
    }

    pub async fn ensure_admin(&self, username: &str, password: &str) -> Result<bool> {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users)")
            .fetch_one(&self.pool)
            .await?;
        if exists {
            return Ok(false);
        }
        let hash = hash_password(password)?;
        sqlx::query("INSERT INTO users(username,password_hash,role) VALUES($1,$2,'administrator')")
            .bind(username)
            .bind(hash)
            .execute(&self.pool)
            .await?;
        Ok(true)
    }

    pub async fn login(&self, username: &str, password: &str) -> Result<String> {
        let row = sqlx::query("SELECT id,password_hash,enabled FROM users WHERE username=$1")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| anyhow!("invalid credentials"))?;
        if !row.get::<bool, _>("enabled") {
            return Err(anyhow!("account disabled"));
        }
        let hash: String = row.get("password_hash");
        verify_password(&hash, password)?;
        let user_id: Uuid = row.get("id");
        let raw = rand::random::<[u8; 32]>();
        let token = hex_encode(&raw);
        let token_hash = token_hash(&token);
        sqlx::query(
            "INSERT INTO auth_sessions(user_id,token_hash,expires_at) VALUES($1,$2,now()+interval '12 hours')",
        )
        .bind(user_id)
        .bind(token_hash)
        .execute(&self.pool)
        .await?;
        Ok(token)
    }

    pub async fn authenticate(&self, token: &str) -> Result<UserIdentity> {
        let hash = token_hash(token);
        let row = sqlx::query(
            r#"SELECT u.id,u.username,u.role FROM auth_sessions s
               JOIN users u ON u.id=s.user_id
               WHERE s.token_hash=$1 AND s.expires_at>now() AND u.enabled=true"#,
        )
        .bind(hash)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| anyhow!("unauthorized"))?;
        Ok(UserIdentity {
            id: row.get("id"),
            username: row.get("username"),
            role: row.get("role"),
        })
    }

    pub async fn logout(&self, token: &str) -> Result<()> {
        sqlx::query("DELETE FROM auth_sessions WHERE token_hash=$1")
            .bind(token_hash(token))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn audit(
        &self,
        user_id: Uuid,
        action: &str,
        object_type: &str,
        object_id: Option<&str>,
        after: Option<&Value>,
    ) -> Result<()> {
        sqlx::query("INSERT INTO audit_log(user_id,action,object_type,object_id,after_state) VALUES($1,$2,$3,$4,$5)")
            .bind(user_id)
            .bind(action)
            .bind(object_type)
            .bind(object_id)
            .bind(after)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

fn hash_password(password: &str) -> Result<String> {
    let salt_bytes = rand::random::<[u8; 16]>();
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|e| anyhow!(e.to_string()))?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| anyhow!(e.to_string()))
}

fn verify_password(hash: &str, password: &str) -> Result<()> {
    let parsed = PasswordHash::new(hash).map_err(|e| anyhow!(e.to_string()))?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .map_err(|_| anyhow!("invalid credentials"))
}

fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_round_trip() {
        let hash = hash_password("correct horse battery staple").unwrap();
        verify_password(&hash, "correct horse battery staple").unwrap();
        assert!(verify_password(&hash, "wrong").is_err());
    }

    #[test]
    fn token_hash_is_stable() {
        assert_eq!(token_hash("abc"), token_hash("abc"));
        assert_ne!(token_hash("abc"), token_hash("def"));
    }
}
