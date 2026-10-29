// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Bus
// SPDX-License-Identifier: Apache-2.0

//! The blocking-consume connection pool - the invariant
//! (`DESIGN.md` §8 invariant 10): a blocking `XREADGROUP` from the HTTP
//! consume handler NEVER occupies the shared command client.
//!
//! The defect this pool removes: every `POST /v1/consume` blocking read
//! used the shared multiplexed GLIDE client, where it serialized behind
//! all other Valkey traffic. A 1s-block poll loop that re-fires the
//! instant an empty batch returns then holds the shared client in
//! blocking reads almost continuously, pins the GLIDE watchdog's
//! process-global pending count above its `SystemOverload` threshold
//! (~200 idle SSE consumers already register there), and sustains a
//! timeout storm in which each miss silently returns an empty batch
//! (`Err(_) => vec![]`) - the caller re-polls, and the storm feeds
//! itself.
//!
//! The pool is a fixed set of DEDICATED GLIDE clients - the same
//! discipline `sse.rs` applies per SSE connection and the SDK's
//! `StreamSubscriber` applies per durable consumer (group DESIGN §3.1):
//! a blocking read can never stall anyone else's XADD/ACK/PUBLISH, and
//! the pool size (not the caller population) bounds how many blocking
//! reads run concurrently - surplus callers queue at acquire, so a
//! poller storm cannot multiply into unbounded Valkey connections.

use std::sync::Arc;

use glide::GlideClient;
use tokio::sync::{Mutex, Semaphore};

/// The pool - the fixed client set plus the permit semaphore that hands
/// them out one-to-one. Acquire is FIFO-fair under contention
/// (`tokio::sync::Semaphore`).
pub struct ConsumePool {
    clients: Mutex<Vec<GlideClient>>,
    permits: Arc<Semaphore>,
    valkey_url: String,
    size: usize,
}

impl ConsumePool {
    /// Build the pool eagerly - every client is connected at boot so the
    /// first blocking consume never pays a TLS handshake on the request
    /// path. A failed connection does NOT abort boot: the slot is
    /// retried on demand at acquire time (the same fail-open posture the
    /// SSE handler applies to its per-connection client).
    ///
    /// # Errors
    /// Returns the LAST connection error only when EVERY client fails to
    /// connect - a partially connected pool still serves traffic.
    pub async fn connect(valkey_url: &str, size: usize) -> anyhow::Result<Self> {
        let size = size.max(1);
        let mut clients = Vec::with_capacity(size);
        let mut last_err = None;
        for _ in 0..size {
            match sentin8::middleware::valkey_client(valkey_url, "sentin8:bus").await {
                Ok(c) => clients.push(c),
                Err(e) => last_err = Some(anyhow::anyhow!(e.to_string())),
            }
        }
        if clients.is_empty() {
            return Err(last_err
                .unwrap_or_else(|| anyhow::anyhow!("consume pool: zero clients configured")));
        }
        Ok(Self {
            clients: Mutex::new(clients),
            permits: Arc::new(Semaphore::new(size)),
            valkey_url: valkey_url.to_string(),
            size,
        })
    }

    /// The pool's configured client count (a gauge/metrics surface).
    pub fn size(&self) -> usize {
        self.size
    }

    /// Acquire a dedicated client for one blocking read. Waits (FIFO)
    /// when all clients are busy - a saturated pool delays surplus
    /// pollers rather than multiplying connections.
    ///
    /// # Errors
    /// Returns an error only if the acquired slot must (re)connect and
    /// the connection attempt fails - the caller surfaces 503, the same
    /// posture as the SSE handler's connection failure.
    pub async fn acquire(&self) -> anyhow::Result<LeasedClient<'_>> {
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| anyhow::anyhow!("consume pool: semaphore closed"))?;
        let mut slots = self.clients.lock().await;
        let client = match slots.pop() {
            Some(c) => c,
            None => {
                // All clients were taken but a permit freed without the
                // client returning - a bug in the release path. Reconnect
                // rather than fail the read.
                sentin8::middleware::valkey_client(&self.valkey_url, "sentin8:bus")
                    .await
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?
            }
        };
        Ok(LeasedClient {
            client: Some(client),
            pool: self,
            _permit: permit,
        })
    }
}

/// A leased dedicated client - returned to the pool on drop, so a
/// handler panic or early return can never strand a slot.
pub struct LeasedClient<'a> {
    client: Option<GlideClient>,
    pool: &'a ConsumePool,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl LeasedClient<'_> {
    /// The leased client for the blocking command.
    pub fn client(&self) -> &GlideClient {
        self.client
            .as_ref()
            .expect("leased client present until drop")
    }
}

impl Drop for LeasedClient<'_> {
    fn drop(&mut self) {
        if let Some(client) = self.client.take() {
            // Synchronous return into the pool: the Mutex is held only
            // for the push; a contended lock here would only delay this
            // drop's task, not block the acquirer (which awaits).
            if let Ok(mut slots) = self.pool.clients.try_lock() {
                slots.push(client);
            }
            // A failed try_lock means an acquirer holds it; the permit
            // still released on drop, so acquire() reconnects a fresh
            // client for the freed slot (self-healing, bounded by size).
        }
    }
}
