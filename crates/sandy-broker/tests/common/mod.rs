//! Shared fixture for the broker's tier-2 acceptance tests: an in-process sandyd on
//! a real UDS, the broker in front of it, and a real HTTP client.
#![allow(dead_code, reason = "shared by several test binaries; each uses a subset")]

use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use reqwest::{Client as Http, StatusCode};
use sandy_broker::{BrokerConfig, Client, IsolationClass, Running, Tuning, serve_with_tuning};
use sandy_fabric_local::{agent::TTY_STDOUT, channel::MembershipId};
use sandy_proto::{MessageType, Tty};
use sandyd::{
    dispatch::JobRegistry, environment_store::EnvironmentStore, host_registry::HostRegistry, store::JobStore,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::{UnixListener, UnixStream};

pub const TOKEN_A: &str = "token-of-client-a";
pub const TOKEN_B: &str = "token-of-client-b";
pub const TOKEN_C: &str = "token-of-client-c";

pub struct Fixture {
    pub base: String,
    pub store: Arc<JobStore>,
    pub registry: Arc<JobRegistry>,
    /// Every cap (hex) the broker presented on the attach socket, in order.
    pub caps: Arc<std::sync::Mutex<Vec<String>>>,
    pub environments: Arc<EnvironmentStore>,
    pub http: Http,
    pub _broker: Running,
    pub _dir: tempfile::TempDir,
    pub root_a: std::path::PathBuf,
}

/// Knobs for [`fixture_with_opts`].
#[derive(Clone, Copy)]
pub struct Opts {
    /// Bind sandyd's attach data-plane socket. Without it every join fails.
    pub attach_socket: bool,
    /// How long a stream ticket lives.
    pub ticket_ttl: Duration,
    /// How long a write to a client that stopped reading may block.
    pub send_timeout: Duration,
    /// Bytes of one job's output the broker keeps.
    pub output_job_cap: usize,
    /// Bytes of output the broker keeps across all clients.
    pub output_total_cap: usize,
    /// How long a finished job's output stays readable.
    pub output_retention: Duration,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            attach_socket: true,
            ticket_ttl: Duration::from_secs(30),
            send_timeout: Duration::from_secs(30),
            output_job_cap: Tuning::default().output_job_cap,
            output_total_cap: Tuning::default().output_total_cap,
            output_retention: Tuning::default().output_retention,
        }
    }
}

pub fn client(id: &str, token: &str, max: IsolationClass, roots: Vec<std::path::PathBuf>) -> Client {
    Client {
        id: id.to_owned(),
        token_sha256: hex::encode(Sha256::digest(token.as_bytes())),
        max_isolation_class: max,
        max_environments: 4,
        max_environment_records: 64,
        profiles: ["dev", "prod", "other"].map(String::from).to_vec(),
        roots,
    }
}

pub async fn fixture() -> Result<Fixture> {
    fixture_with_env_quota(4).await
}

pub async fn fixture_with_opts(opts: Opts) -> Result<Fixture> {
    build(4, 64, opts, None, None).await
}

/// A fixture whose client `a` may hold `max_environments` environments.
pub async fn fixture_with_env_quota(max_environments: usize) -> Result<Fixture> {
    fixture_with_limits(max_environments, 64).await
}

/// A fixture whose client `a` may hold `max_environments` live environments and ever
/// create `max_environment_records`.
pub async fn fixture_with_limits(max_environments: usize, max_environment_records: usize) -> Result<Fixture> {
    fixture_with_row_cap(max_environments, max_environment_records, None).await
}

/// [`fixture_with_limits`] over a sandyd whose environment table holds at most `row_cap` live rows.
pub async fn fixture_with_row_cap(
    max_environments: usize,
    max_environment_records: usize,
    row_cap: Option<usize>,
) -> Result<Fixture> {
    build(
        max_environments,
        max_environment_records,
        Opts::default(),
        row_cap,
        None,
    )
    .await
}

/// [`fixture_with_limits`] with `owners_json` written as the broker's owner table before it
/// starts. `seed` runs first on sandyd's store so the table can name rows that exist there.
pub async fn fixture_with_owner_table(
    max_environments: usize,
    max_environment_records: usize,
    seed: impl FnOnce(&EnvironmentStore) -> Result<String> + 'static,
) -> Result<Fixture> {
    build(
        max_environments,
        max_environment_records,
        Opts::default(),
        None,
        Some(Box::new(seed)),
    )
    .await
}

type OwnerSeed = Box<dyn FnOnce(&EnvironmentStore) -> Result<String>>;

async fn build(
    max_environments: usize,
    max_environment_records: usize,
    opts: Opts,
    row_cap: Option<usize>,
    owner_seed: Option<OwnerSeed>,
) -> Result<Fixture> {
    let dir = tempfile::tempdir()?;
    let socket = dir.path().join("sandyd.sock");
    let store = Arc::new(JobStore::open_in_memory()?);
    let environments = Arc::new(EnvironmentStore::open_in_memory()?.with_max_rows(row_cap));
    if let Some(seed) = owner_seed {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let json = seed(&environments)?;
        let state = dir.path().join("state");
        std::fs::create_dir(&state)?;
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(state.join("owners.json"))?;
        std::io::Write::write_all(&mut file, json.as_bytes())?;
    }
    let registry = Arc::new(JobRegistry::new()?);
    let hosts = Arc::new(HostRegistry::default());
    let listener = UnixListener::bind(&socket)?;
    let caps = Arc::new(std::sync::Mutex::new(Vec::new()));
    if opts.attach_socket {
        // sandyd's accept loop listens on a private path. The canonical attach path holds a
        // recording proxy, so a test can see which cap the broker presented.
        let real_path = dir.path().join("real-attach.sock");
        let real = UnixListener::bind(&real_path)?;
        let (r, h) = (Arc::clone(&registry), Arc::clone(&hosts));
        tokio::spawn(async move { sandyd::attach_relay::serve_attach_accept_loop(&real, &r, &h).await });
        let proxy = UnixListener::bind(sandy_control_proto::attach_socket_path(&socket))?;
        let seen = Arc::clone(&caps);
        tokio::spawn(async move {
            while let Ok((client, _)) = proxy.accept().await {
                tokio::spawn(record_and_forward(client, real_path.clone(), Arc::clone(&seen)));
            }
        });
    }
    let (s, e, r, h) = (
        Arc::clone(&store),
        Arc::clone(&environments),
        Arc::clone(&registry),
        hosts,
    );
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(sandyd::serve_connection(
                stream,
                Arc::clone(&s),
                Arc::clone(&e),
                Arc::clone(&r),
                Arc::clone(&h),
                None,
            ));
        }
    });
    let root_a = dir.path().join("root-a");
    std::fs::create_dir(&root_a)?;
    let broker = serve_with_tuning(
        BrokerConfig {
            control_socket: socket,
            rpc_deadline: std::time::Duration::from_secs(30),
            state_dir: dir.path().join("state"),
            bind: "127.0.0.1:0".parse()?,
            clients: vec![
                Client {
                    max_environments,
                    max_environment_records,
                    ..client("a", TOKEN_A, IsolationClass::Trusted, vec![root_a.clone()])
                },
                client("b", TOKEN_B, IsolationClass::Untrusted, vec![]),
                client("c", TOKEN_C, IsolationClass::Trusted, vec![]),
            ],
        },
        Tuning {
            ticket_ttl: opts.ticket_ttl,
            send_timeout: opts.send_timeout,
            output_job_cap: opts.output_job_cap,
            output_total_cap: opts.output_total_cap,
            output_retention: opts.output_retention,
            ..Tuning::default()
        },
    )
    .await?;
    Ok(Fixture {
        base: format!("http://{}", broker.addr),
        store,
        registry,
        caps,
        environments,
        http: Http::new(),
        _broker: broker,
        _dir: dir,
        root_a,
    })
}

async fn record_and_forward(
    mut client: UnixStream,
    real: std::path::PathBuf,
    seen: Arc<std::sync::Mutex<Vec<String>>>,
) {
    use sandy_fabric_local::link::{LinkFrame, read_frame, write_frame};
    let Ok(Some(join)) = read_frame(&mut client).await else {
        return;
    };
    if let LinkFrame::Join { cap, .. } = &join
        && let Ok(mut seen) = seen.lock()
    {
        seen.push(cap.clone());
    }
    let Ok(mut upstream) = UnixStream::connect(real).await else {
        return;
    };
    if write_frame(&mut upstream, &join).await.is_ok() {
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    }
}

pub fn submit_body() -> Value {
    json!({"manifest": "bQ==", "manifest_encoding": "test/v1", "required_isolation_class": "trusted"})
}

impl Fixture {
    pub async fn call(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> Result<(StatusCode, Value)> {
        let mut req = self.http.request(method.parse()?, format!("{}{path}", self.base));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        Ok((status, serde_json::from_str(&text).unwrap_or(Value::String(text))))
    }

    pub async fn submit(&self, token: &str) -> Result<String> {
        let (status, body) = self.call("POST", "/v1/jobs", Some(token), Some(submit_body())).await?;
        assert_eq!(status, StatusCode::ACCEPTED, "submit failed: {body}");
        Ok(body["job_id"].as_str().context("job_id")?.to_owned())
    }
}

/// The job's agent, joined to its channel: posts output the way the sandbox agent does.
pub struct Agent {
    channel: Arc<
        sandy_fabric_local::channel::Channel<sandy_fabric_local::inmem::InMem, sandy_fabric_local::SharedCapAuthority>,
    >,
    membership: MembershipId,
}

impl Agent {
    pub async fn post(&self, content_type: &str, bytes: &[u8]) -> Result<()> {
        self.channel
            .post(
                &self.membership,
                Some(MessageType::Tty(Tty {})),
                content_type,
                bytes.to_vec(),
            )
            .await
            .context("agent post")?;
        Ok(())
    }

    pub async fn stdout(&self, bytes: &[u8]) -> Result<()> {
        self.post(TTY_STDOUT, bytes).await
    }
}

impl Fixture {
    pub fn agent(&self, job_id: &str) -> Result<Agent> {
        let job = self.registry.get(job_id).context("job has no channel")?;
        let membership = job.channel.join(&job.agent_cap).context("agent join")?;
        Ok(Agent {
            channel: Arc::clone(&job.channel),
            membership,
        })
    }

    /// Ends the job in sandyd's store, as a finished run would.
    pub fn finish(&self, job_id: &str, status: sandy_control_proto::JobStatus) -> Result<()> {
        self.store.finish(job_id, status, Some(0), "")?;
        Ok(())
    }

    /// `POST /v1/jobs/{id}/attach` as `token`, returning the `stream_url`.
    pub async fn attach(&self, id: &str, token: &str) -> Result<String> {
        let (status, body) = self
            .call("POST", &format!("/v1/jobs/{id}/attach"), Some(token), Some(json!({})))
            .await?;
        assert_eq!(status, StatusCode::OK, "attach failed: {body}");
        Ok(body["stream_url"].as_str().context("stream_url")?.to_owned())
    }

    /// Opens a stream URL with `token`'s bearer.
    pub async fn open_stream(&self, url: &str, token: Option<&str>) -> Result<reqwest::Response> {
        let mut req = self.http.get(format!("{}{url}", self.base));
        if let Some(t) = token {
            req = req.bearer_auth(t);
        }
        Ok(req.send().await?)
    }
}

/// Reads NDJSON lines off a streaming response.
pub struct Lines {
    resp: reqwest::Response,
    buf: Vec<u8>,
    /// Every line read so far, raw, for leak scans.
    pub transcript: String,
}

impl Lines {
    pub fn new(resp: reqwest::Response) -> Self {
        Self {
            resp,
            buf: Vec::new(),
            transcript: String::new(),
        }
    }

    /// The next line as JSON, or `None` when the body ended. Fails after 15 s of silence.
    pub async fn next(&mut self) -> Result<Option<Value>> {
        loop {
            if let Some(end) = self.buf.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=end).collect();
                self.transcript.push_str(&String::from_utf8_lossy(&line));
                return Ok(Some(
                    serde_json::from_slice(&line[..line.len() - 1]).context("a line is JSON")?,
                ));
            }
            let chunk = tokio::time::timeout(Duration::from_secs(15), self.resp.chunk())
                .await
                .context("stream went silent")??;
            match chunk {
                Some(c) => self.buf.extend_from_slice(&c),
                None => {
                    assert!(self.buf.is_empty(), "the body ended inside a line");
                    return Ok(None);
                }
            }
        }
    }

    /// Reads `output` lines until `want` bytes arrived, returning the decoded bytes.
    pub async fn output_bytes(&mut self, want: usize) -> Result<Vec<u8>> {
        use base64::Engine;
        let mut got = Vec::new();
        while got.len() < want {
            let line = self.next().await?.context("the stream ended early")?;
            assert_eq!(line["type"], "output", "unexpected line {line}");
            got.extend(base64::engine::general_purpose::STANDARD.decode(line["data"].as_str().context("data")?)?);
        }
        Ok(got)
    }

    /// Reads to the end, returning the last line.
    pub async fn last(&mut self) -> Result<Value> {
        let mut last = None;
        while let Some(line) = self.next().await? {
            last = Some(line);
        }
        last.context("empty stream")
    }
}
