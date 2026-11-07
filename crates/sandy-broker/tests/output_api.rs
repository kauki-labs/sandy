//! Tier-2 acceptance for `GET /v1/jobs/{id}/output` (#643): the broker keeps a bounded copy of each
//! job's output and serves it by absolute offset, during the run and for a window after it.

mod common;

use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;
use common::{Fixture, Opts, TOKEN_A, TOKEN_B, TOKEN_C, fixture, fixture_with_opts};
use reqwest::StatusCode;
use sandy_control_proto::JobStatus;
use serde_json::Value;

const WAIT: Duration = Duration::from_secs(10);

/// The documented ceiling of one read.
const MAX_READ: usize = 256 * 1024;

fn decode(body: &Value) -> Result<Vec<u8>> {
    Ok(base64::engine::general_purpose::STANDARD.decode(body["data"].as_str().context("data")?)?)
}

impl Fixture {
    async fn output(&self, id: &str, token: &str, query: &str) -> Result<(StatusCode, Value)> {
        self.call("GET", &format!("/v1/jobs/{id}/output?{query}"), Some(token), None)
            .await
    }

    /// Polls until the broker's `next_offset` reaches `want`, then returns that response.
    async fn output_until(&self, id: &str, query: &str, want: u64) -> Result<Value> {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            let (status, body) = self.output(id, TOKEN_A, query).await?;
            assert_eq!(status, StatusCode::OK, "{body}");
            if body["next_offset"].as_u64() >= Some(want) {
                return Ok(body);
            }
            if tokio::time::Instant::now() > deadline {
                bail!("output never reached offset {want}: {body}");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Polls until the broker reports the job done.
    async fn output_done(&self, id: &str) -> Result<Value> {
        self.output_done_as(id, TOKEN_A).await
    }

    async fn output_done_as(&self, id: &str, token: &str) -> Result<Value> {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            let (status, body) = self.output(id, token, "offset=0").await?;
            assert_eq!(status, StatusCode::OK, "{body}");
            if body["done"] == true {
                return Ok(body);
            }
            if tokio::time::Instant::now() > deadline {
                bail!("the job never read as done: {body}");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

#[tokio::test]
async fn the_owner_reads_a_running_jobs_output_by_offset() -> Result<()> {
    let f = fixture().await?;
    let id = f.submit(TOKEN_A).await?;
    let agent = f.agent(&id)?;
    agent.stdout(b"hello ").await?;
    agent.stdout(b"world").await?;

    let all = f.output_until(&id, "offset=0", 11).await?;
    assert_eq!(decode(&all)?, b"hello world");
    assert_eq!(all["offset"], 0);
    assert_eq!(all["next_offset"], 11);
    assert_eq!(all["dropped"], 0);
    assert_eq!(all["done"], false);

    let (status, tail) = f.output(&id, TOKEN_A, "offset=6").await?;
    assert_eq!(status, StatusCode::OK, "{tail}");
    assert_eq!(
        (decode(&tail)?, &tail["offset"], &tail["next_offset"]),
        (b"world".to_vec(), &6.into(), &11.into())
    );

    let (_, empty) = f.output(&id, TOKEN_A, "offset=11").await?;
    assert_eq!((decode(&empty)?, &empty["next_offset"]), (Vec::new(), &11.into()));
    Ok(())
}

#[tokio::test]
async fn the_output_is_still_readable_after_the_job_exits() -> Result<()> {
    let f = fixture().await?;
    let id = f.submit(TOKEN_A).await?;
    f.agent(&id)?.stdout(b"before exit").await?;
    f.output_until(&id, "offset=0", 11).await?;

    f.finish(&id, JobStatus::Succeeded)?;
    let done = f.output_done(&id).await?;
    assert_eq!(done["state"], "succeeded", "{done}");
    assert_eq!(decode(&done)?, b"before exit");
    assert_eq!(done["next_offset"], 11);
    Ok(())
}

#[tokio::test]
async fn another_client_gets_the_same_404_as_for_an_unknown_job() -> Result<()> {
    let f = fixture().await?;
    let id = f.submit(TOKEN_A).await?;
    f.agent(&id)?.stdout(b"private").await?;
    f.output_until(&id, "offset=0", 7).await?;

    let (status, foreign) = f.output(&id, TOKEN_B, "offset=0").await?;
    let (unknown_status, unknown) = f.output("no-such-job", TOKEN_B, "offset=0").await?;
    assert_eq!((status, &foreign), (StatusCode::NOT_FOUND, &unknown));
    assert_eq!(
        (unknown_status, &foreign["code"]),
        (StatusCode::NOT_FOUND, &"not_found".into())
    );

    let (status, body) = f.call("GET", &format!("/v1/jobs/{id}/output"), None, None).await?;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::UNAUTHORIZED, &"unauthenticated".into())
    );
    Ok(())
}

#[tokio::test]
async fn an_offset_behind_the_cap_reports_the_dropped_bytes() -> Result<()> {
    let f = fixture_with_opts(Opts {
        output_job_cap: 8,
        ..Opts::default()
    })
    .await?;
    let id = f.submit(TOKEN_A).await?;
    let agent = f.agent(&id)?;
    agent.stdout(b"0123456789").await?;
    agent.stdout(b"abcdefghij").await?;

    let body = f.output_until(&id, "offset=0", 20).await?;
    assert_eq!(body["dropped"], 12, "{body}");
    assert_eq!(body["offset"], 12);
    assert_eq!(decode(&body)?, b"cdefghij");

    let (_, inside) = f.output(&id, TOKEN_A, "offset=16").await?;
    assert_eq!(
        (inside["dropped"].as_u64(), decode(&inside)?),
        (Some(0), b"ghij".to_vec())
    );
    Ok(())
}

#[tokio::test]
async fn limit_bounds_one_read_and_is_clamped() -> Result<()> {
    let f = fixture().await?;
    let id = f.submit(TOKEN_A).await?;
    let agent = f.agent(&id)?;
    let chunk = vec![b'x'; 100 * 1024];
    for _ in 0..3 {
        agent.stdout(&chunk).await?;
    }
    let total = 3 * chunk.len() as u64;
    // A read at the last byte is refused (400) until that byte has arrived.
    let deadline = tokio::time::Instant::now() + WAIT;
    while f.output(&id, TOKEN_A, &format!("offset={}", total - 1)).await?.0 != StatusCode::OK {
        assert!(tokio::time::Instant::now() < deadline, "the output never arrived");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let (_, three) = f.output(&id, TOKEN_A, "offset=0&limit=3").await?;
    assert_eq!((decode(&three)?.len(), &three["next_offset"]), (3, &3.into()));

    for query in ["offset=0&limit=1000000000", "offset=0&limit=0", "offset=0"] {
        let (status, body) = f.output(&id, TOKEN_A, query).await?;
        assert_eq!(status, StatusCode::OK, "{query}: {body}");
        let len = decode(&body)?.len();
        assert!((1..=MAX_READ).contains(&len), "{query} returned {len} bytes");
    }
    let (_, huge) = f.output(&id, TOKEN_A, "offset=0&limit=1000000000").await?;
    assert_eq!(
        decode(&huge)?.len(),
        MAX_READ,
        "the limit must clamp to the ceiling, not to the data"
    );
    Ok(())
}

#[tokio::test]
async fn an_offset_past_the_end_or_a_malformed_query_is_invalid() -> Result<()> {
    let f = fixture().await?;
    let id = f.submit(TOKEN_A).await?;
    f.agent(&id)?.stdout(b"abc").await?;
    f.output_until(&id, "offset=0", 3).await?;
    for query in ["offset=4", "offset=-1", "offset=x", "limit=1.5", "offset=0&bogus=1"] {
        let (status, body) = f.output(&id, TOKEN_A, query).await?;
        assert_eq!(
            (status, &body["code"]),
            (StatusCode::BAD_REQUEST, &"invalid_request".into()),
            "{query}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_finished_jobs_output_is_gone_after_the_retention_window() -> Result<()> {
    let f = fixture_with_opts(Opts {
        output_retention: Duration::from_millis(400),
        ..Opts::default()
    })
    .await?;
    let id = f.submit(TOKEN_A).await?;
    f.agent(&id)?.stdout(b"short lived").await?;
    f.output_until(&id, "offset=0", 11).await?;
    f.finish(&id, JobStatus::Succeeded)?;
    f.output_done(&id).await?;

    tokio::time::sleep(Duration::from_millis(900)).await;
    let (status, body) = f.output(&id, TOKEN_A, "offset=0").await?;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::NOT_FOUND, &"not_found".into()),
        "{body}"
    );
    // The job itself is still the owner's: only its output expired.
    let (status, _) = f.call("GET", &format!("/v1/jobs/{id}"), Some(TOKEN_A), None).await?;
    assert_eq!(status, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn a_job_still_running_keeps_its_output_past_the_retention_window() -> Result<()> {
    let f = fixture_with_opts(Opts {
        output_retention: Duration::from_millis(300),
        ..Opts::default()
    })
    .await?;
    let id = f.submit(TOKEN_A).await?;
    f.agent(&id)?.stdout(b"alive").await?;
    f.output_until(&id, "offset=0", 5).await?;
    tokio::time::sleep(Duration::from_millis(800)).await;
    let (status, body) = f.output(&id, TOKEN_A, "offset=0").await?;
    assert_eq!((status, body["done"].clone()), (StatusCode::OK, false.into()), "{body}");
    Ok(())
}

#[tokio::test]
async fn collecting_output_does_not_steal_it_from_an_attach_stream() -> Result<()> {
    let f = fixture().await?;
    let id = f.submit(TOKEN_A).await?;
    let agent = f.agent(&id)?;
    agent.stdout(b"first").await?;
    f.output_until(&id, "offset=0", 5).await?;

    let url = f.attach(&id, TOKEN_A).await?;
    let mut lines = common::Lines::new(f.open_stream(&url, Some(TOKEN_A)).await?);
    agent.stdout(b"second").await?;
    assert_eq!(lines.output_bytes(11).await?, b"firstsecond");
    let all = f.output_until(&id, "offset=0", 11).await?;
    assert_eq!(decode(&all)?, b"firstsecond");
    Ok(())
}

#[tokio::test]
async fn one_clients_output_never_evicts_another_clients_buffers() -> Result<()> {
    // Three clients share 30 bytes: 10 each.
    let f = fixture_with_opts(Opts {
        output_job_cap: 8,
        output_total_cap: 30,
        ..Opts::default()
    })
    .await?;
    let b = f.submit(TOKEN_C).await?;
    f.agent(&b)?.stdout(b"bbbbbb").await?;
    let deadline = tokio::time::Instant::now() + WAIT;
    while f.output(&b, TOKEN_C, "offset=5").await?.0 != StatusCode::OK {
        assert!(tokio::time::Instant::now() < deadline, "b's output never arrived");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    f.finish(&b, JobStatus::Succeeded)?;
    f.output_done_as(&b, TOKEN_C).await?;

    // Client a overruns its share with two jobs of 8 bytes.
    let a1 = f.submit(TOKEN_A).await?;
    f.agent(&a1)?.stdout(b"aaaaaaaa").await?;
    f.output_until(&a1, "offset=0", 8).await?;
    f.finish(&a1, JobStatus::Succeeded)?;
    f.output_done(&a1).await?;
    let a2 = f.submit(TOKEN_A).await?;
    f.agent(&a2)?.stdout(b"AAAAAAAA").await?;
    f.output_until(&a2, "offset=0", 8).await?;

    let (status, kept) = f.output(&b, TOKEN_C, "offset=0").await?;
    assert_eq!(status, StatusCode::OK, "a's output evicted b's buffer: {kept}");
    assert_eq!(decode(&kept)?, b"bbbbbb");
    let (status, _) = f.output(&a1, TOKEN_A, "offset=0").await?;
    assert_eq!(status, StatusCode::NOT_FOUND, "a's own oldest finished job goes first");
    let (status, live) = f.output(&a2, TOKEN_A, "offset=0").await?;
    assert_eq!((status, decode(&live)?), (StatusCode::OK, b"AAAAAAAA".to_vec()));
    Ok(())
}

#[tokio::test]
async fn an_absurd_retention_does_not_panic() -> Result<()> {
    let f = fixture_with_opts(Opts {
        output_retention: Duration::MAX,
        ..Opts::default()
    })
    .await?;
    let id = f.submit(TOKEN_A).await?;
    f.agent(&id)?.stdout(b"x").await?;
    f.output_until(&id, "offset=0", 1).await?;
    f.finish(&id, JobStatus::Succeeded)?;
    let done = f.output_done(&id).await?;
    assert_eq!(done["done"], true);
    let (status, _) = f.output(&id, TOKEN_A, "offset=0").await?;
    assert_eq!(status, StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn dropping_the_broker_stops_its_collectors() -> Result<()> {
    let f = fixture().await?;
    let id = f.submit(TOKEN_A).await?;
    let job = f.registry.get(&id).context("job")?;
    let deadline = tokio::time::Instant::now() + WAIT;
    // sandyd's own archive persister is always one member; the collector is the second.
    while job.channel.member_count() < 2 {
        assert!(tokio::time::Instant::now() < deadline, "the collector never joined");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let common::Fixture { _broker, .. } = f;
    drop(_broker);
    let deadline = tokio::time::Instant::now() + WAIT;
    while job.channel.member_count() > 1 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the collector outlived the broker"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Ok(())
}
