use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce as AesNonce, Key
};
use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature};
use reqwest::Client;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use std::time::Duration;
use rand::RngCore;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SealedEvent {
    pub payload_hash: String,
    pub agent_id: String,
    pub local_timestamp: u64,
    pub nonce: String,
    pub device_id: String,
    pub device_signature: String,
    pub payload_json: String,
    pub action_status: String,
}

#[derive(Clone)]
pub struct LedgerClient {
    http_client: Client,
    db_conn: Arc<Mutex<Connection>>,
    signing_key: Arc<SigningKey>,
    device_id: String,
    ledger_url: String,
    encryption_key: Key<Aes256Gcm>,
    ledger_pub_key: VerifyingKey,
    lease_expires_at: Arc<Mutex<Option<u64>>>,
}

impl LedgerClient {
    pub fn new() -> Self {
        let private_key_hex = env::var("ACCOUNTABILITY_PRIVATE_KEY")
            .unwrap_or_else(|_| panic!("ACCOUNTABILITY_PRIVATE_KEY environment variable is required"));
            
        let private_key_bytes = hex::decode(&private_key_hex).expect("Invalid hex for private key");
        let private_key_array: [u8; 32] = private_key_bytes.try_into().expect("Private key must be 32 bytes");
        let signing_key = SigningKey::from_bytes(&private_key_array);

        let device_id = env::var("ACCOUNTABILITY_DEVICE_ID")
            .unwrap_or_else(|_| "default-device-id".to_string());
            
        let ledger_url = env::var("LEDGER_URL")
            .unwrap_or_else(|_| "http://localhost:8000".to_string());
        
        let parsed_url = url::Url::parse(&ledger_url).unwrap_or_else(|_| panic!("LEDGER_URL is invalid"));
        
        let scheme = parsed_url.scheme();
        let host = parsed_url.host_str().unwrap_or("");
        
        if scheme == "http" {
            if host != "localhost" && host != "127.0.0.1" && host != "::1" {
                panic!("LEDGER_URL must be https:// unless using localhost loopback");
            }
        } else if scheme != "https" {
            panic!("LEDGER_URL must use http or https scheme");
        }

        let ledger_pub_key = match env::var("LEDGER_PUBLIC_KEY") {
            Ok(hex_str) => {
                let bytes = hex::decode(&hex_str).expect("Invalid LEDGER_PUBLIC_KEY hex");
                let array: [u8; 32] = bytes.try_into().expect("Ledger pubkey must be 32 bytes");
                VerifyingKey::from_bytes(&array).expect("Invalid Ed25519 ledger pubkey")
            }
            Err(_) => {
                panic!("LEDGER_PUBLIC_KEY environment variable is strictly required for cryptographically verified receipts");
            }
        };

        let queue_db_path = env::var("ACCOUNTABILITY_QUEUE_DB_PATH")
            .expect("ACCOUNTABILITY_QUEUE_DB_PATH environment variable must be set");

        let encryption_key_hex = env::var("ACCOUNTABILITY_ENCRYPTION_KEY")
            .expect("ACCOUNTABILITY_ENCRYPTION_KEY environment variable must be set");
        let encryption_key_bytes = hex::decode(encryption_key_hex)
            .expect("Invalid hex for ACCOUNTABILITY_ENCRYPTION_KEY");
        if encryption_key_bytes.len() != 32 {
            panic!("ACCOUNTABILITY_ENCRYPTION_KEY must be exactly 32 bytes (64 hex chars)");
        }
        let encryption_key = *Key::<Aes256Gcm>::from_slice(&encryption_key_bytes);

        let conn = Connection::open(queue_db_path).expect("Failed to open local queue database");
        


        conn.execute(
            "CREATE TABLE IF NOT EXISTS local_audit_log (
                nonce TEXT,
                action_status TEXT,
                payload_hash TEXT,
                agent_id TEXT,
                local_timestamp INTEGER,
                device_id TEXT,
                device_signature TEXT,
                payload_json TEXT,
                receipt_signature TEXT,
                ledger_timestamp INTEGER,
                json_rpc_id TEXT,
                PRIMARY KEY (nonce, action_status)
            )",
            [],
        ).unwrap();

        conn.execute(
            "CREATE TABLE IF NOT EXISTS receipts (
                nonce TEXT,
                action_status TEXT,
                receipt_signature TEXT,
                ledger_timestamp INTEGER,
                PRIMARY KEY (nonce, action_status)
            )",
            [],
        ).unwrap();

        Self {
            http_client: Client::builder().timeout(Duration::from_secs(5)).build().unwrap(),
            db_conn: Arc::new(Mutex::new(conn)),
            signing_key: Arc::new(signing_key),
            device_id,
            ledger_url,
            encryption_key,
            ledger_pub_key,
            lease_expires_at: Arc::new(Mutex::new(None)),
        }
    }



    pub async fn has_nonce(&self, nonce: &str) -> bool {
        let conn = self.db_conn.lock().await;
        let mut stmt = match conn.prepare("SELECT 1 FROM local_audit_log WHERE nonce = ?1") {
            Ok(s) => s,
            Err(_) => return false,
        };
        stmt.exists(rusqlite::params![nonce]).unwrap_or(false)
    }


    pub async fn ensure_lease(&self) -> Result<(), String> {
        let mut lease_lock = self.lease_expires_at.lock().await;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        if let Some(exp) = *lease_lock {
            if now < exp {
                return Ok(());
            }
        }
        
        let body = serde_json::json!({
            "device_id": self.device_id
        });
        
        match self.http_client.post(format!("{}/lease", self.ledger_url)).json(&body).send().await {
            Ok(res) if res.status().is_success() => {
                if let Ok(json) = res.json::<Value>().await {
                    if let (Some(exp), Some(sig_hex)) = (json.get("expires_at").and_then(|v| v.as_u64()), json.get("lease_signature").and_then(|v| v.as_str())) {
                        let msg = format!("LEASE:{}:{}", self.device_id, exp);
                        if let Ok(sig_bytes) = hex::decode(sig_hex) {
                            if sig_bytes.len() == 64 {
                                let mut arr = [0u8; 64];
                                arr.copy_from_slice(&sig_bytes);
                                let signature = Signature::from_bytes(&arr);
                                if self.ledger_pub_key.verify(msg.as_bytes(), &signature).is_ok() {
                                    *lease_lock = Some(exp);
                                    return Ok(());
                                }
                            }
                        }
                        return Err("Invalid lease signature cryptographically".to_string());
                    }
                }
                Err("Invalid lease response format".to_string())
            }
            Ok(res) if res.status().as_u16() == 401 || res.status().as_u16() == 403 => {
                Err("Kill-switch engaged. Agent authorization revoked.".to_string())
            }
            res => {
                let status = res.map(|r| r.status().as_u16().to_string()).unwrap_or_else(|_| "Network Error".to_string());
                Err(format!("Accountability proxy denied execution. Ledger returned: {}", status))
            }
        }
    }

    pub async fn insert_local_event(&self, raw_payload: &[u8], action_status: &str, provided_nonce: Option<String>) -> Result<String, String> {
        let mut hasher = Sha256::new();
        hasher.update(raw_payload);
        let payload_hash = hex::encode(hasher.finalize());

        let local_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let nonce = provided_nonce.unwrap_or_else(|| Uuid::new_v4().to_string());
        let agent_id = "autonomous-agent-01".to_string();

        let message = format!("{}:{}:{}:{}:{}:{}", payload_hash, local_timestamp, self.device_id, nonce, agent_id, action_status);
        let signature: Signature = self.signing_key.sign(message.as_bytes());
        let device_signature = hex::encode(signature.to_bytes());

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let aes_nonce = AesNonce::from_slice(&nonce_bytes);
        let cipher_text = Aes256Gcm::new(&self.encryption_key)
            .encrypt(aes_nonce, raw_payload)
            .map_err(|e| format!("Encryption failed: {:?}", e))?;
        let encrypted_payload = format!("{}:{}", hex::encode(nonce_bytes), hex::encode(cipher_text));

        let event = SealedEvent {
            payload_hash: payload_hash.clone(),
            agent_id: agent_id.clone(),
            local_timestamp,
            nonce: nonce.clone(),
            device_id: self.device_id.clone(),
            device_signature: device_signature.clone(),
            payload_json: encrypted_payload.clone(),
            action_status: action_status.to_string(),
        };

        let body = serde_json::json!({
            "payload_hash": event.payload_hash,
            "agent_id": event.agent_id,
            "local_timestamp": event.local_timestamp,
            "nonce": event.nonce,
            "device_id": event.device_id,
            "device_signature": event.device_signature,
            "action_status": event.action_status
        });

        {
            let conn = self.db_conn.lock().await;
            let id_str = if let Ok(val) = serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(raw_payload)) {
            val.get("id").map(|id| {
                if id.is_number() { id.as_i64().unwrap().to_string() }
                else if id.is_string() { id.as_str().unwrap().to_string() }
                else { id.to_string() }
            })
        } else { None };

        conn.execute(
            "INSERT INTO local_audit_log (nonce, action_status, payload_hash, agent_id, local_timestamp, device_id, device_signature, payload_json, json_rpc_id) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                event.nonce,
                event.action_status,
                event.payload_hash,
                event.agent_id,
                event.local_timestamp,
                event.device_id,
                event.device_signature,
                event.payload_json,
                id_str
            ],
        ).map_err(|e| format!("CRITICAL: Failed to durably store event: {}", e))?;
        }

        if std::env::var("CRASH_AFTER_DB_INSERT").is_ok() {
            eprintln!("FAULT INJECTION: Crashing after DB insert but before network dispatch!");
            std::process::exit(9);
        }

        Ok(nonce)
    }

    async fn verify_and_store_receipt(&self, event: &SealedEvent, receipt_sig_hex: &str, ledger_ts: u64, chain_hash: &str, action_status: &str) -> Result<(), String> {
        let receipt_message = format!("{}:{}:{}:{}:{}:{}:{}:{}:{}", 
            event.payload_hash, event.agent_id, event.local_timestamp, 
            event.device_id, event.nonce, event.device_signature, ledger_ts, chain_hash, action_status
        );
        let sig_bytes = hex::decode(receipt_sig_hex).map_err(|_| "Invalid hex in receipt")?;
        let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().map_err(|_| "Invalid signature length")?);
        
        if self.ledger_pub_key.verify(receipt_message.as_bytes(), &signature).is_err() {
            return Err("CRITICAL: Ledger returned an INVALID receipt signature!".to_string());
        }

        let mut conn = self.db_conn.lock().await;
        let tx = conn.transaction().map_err(|e| format!("Failed to start transaction: {}", e))?;
        
        tx.execute(
            "INSERT INTO receipts (nonce, action_status, receipt_signature, ledger_timestamp) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![event.nonce, action_status, receipt_sig_hex, ledger_ts]
        ).map_err(|e| format!("Failed to insert receipt: {}", e))?;
        
        tx.execute(
            "UPDATE local_audit_log SET receipt_signature = ?1, ledger_timestamp = ?2 WHERE nonce = ?3 AND action_status = ?4", 
            rusqlite::params![receipt_sig_hex, ledger_ts, event.nonce, action_status]
        ).map_err(|e| format!("Failed to update local audit log: {}", e))?;
        
        tx.commit().map_err(|e| format!("Failed to commit transaction: {}", e))?;
        
        eprintln!("[ACCOUNTABILITY] 🔄 Successfully verified and stored receipt for: {} ({})", event.nonce, action_status);
        Ok(())
    }

    pub fn start_background_sync(&self) {
        let client = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                client.sync_queue().await;
            }
        });
    }

    pub async fn sync_queue(&self) {
        let event_opt = {
            let conn = self.db_conn.lock().await;
            let mut stmt = match conn.prepare("
                SELECT nonce, payload_hash, agent_id, local_timestamp, device_id, device_signature, payload_json, action_status 
                FROM local_audit_log 
                WHERE receipt_signature IS NULL
                ORDER BY local_timestamp ASC
                LIMIT 1
            ") {
                Ok(s) => s,
                Err(_) => { return; }
            };
            
            let mut rows = match stmt.query([]) {
                Ok(r) => r,
                Err(_) => { return; }
            };

            match rows.next() {
                Ok(Some(row)) => {
                    Some(SealedEvent {
                        nonce: row.get(0).unwrap(),
                        payload_hash: row.get(1).unwrap(),
                        agent_id: row.get(2).unwrap(),
                        local_timestamp: row.get(3).unwrap(),
                        device_id: row.get(4).unwrap(),
                        device_signature: row.get(5).unwrap(),
                        payload_json: row.get(6).unwrap(),
                        action_status: row.get(7).unwrap_or_else(|_| "UNKNOWN".to_string()),
                    })
                }
                _ => None
            }
        };

        if let Some(event) = event_opt {
            let body = serde_json::json!({
                "payload_hash": event.payload_hash,
                "agent_id": event.agent_id,
                "local_timestamp": event.local_timestamp,
                "nonce": event.nonce,
                "device_id": event.device_id,
                "device_signature": event.device_signature,
                "action_status": event.action_status
            });

            match self.http_client.post(format!("{}/seal", self.ledger_url)).json(&body).send().await {
                Ok(res) if res.status().is_success() => {
                    if let Ok(json) = res.json::<Value>().await {
                        if let (Some(sig), Some(ts), Some(ch)) = (
                            json.get("receipt_signature").and_then(|v| v.as_str()),
                            json.get("ledger_timestamp").and_then(|v| v.as_i64()),
                            json.get("chain_hash").and_then(|v| v.as_str())
                        ) {
                            let _ = self.verify_and_store_receipt(&event, sig, ts as u64, ch, &event.action_status).await;
                        }
                    }
                }
                Ok(res) => {
                    eprintln!("CRITICAL: Ledger /seal rejected event! Status: {}", res.status());
                }
                Err(e) => {
                    eprintln!("CRITICAL: Network error sending to /seal: {}", e);
                }
            }
        }
    }
}
