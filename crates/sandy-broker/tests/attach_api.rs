//! Tier-2 acceptance for attach over HTTP (#616): the broker bridges sandyd's attach data plane
//! to an NDJSON stream, behind a single-use ticket and the client's bearer.

mod common;

use std::time::Duration;

use anyhow::{Context, Result};
use common::{Lines, Opts, TOKEN_A, TOKEN_B, fixture, fixture_with_opts};
use reqwest::StatusCode;
use sandy_control_proto::JobStatus;
use sandy_fabric_local::agent::TTY_STDERR;
use serde_json::{Value, json};

const WAIT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn the_owner_streams_agent_output_as_ndjson_then_an_exit_line() -> Result<()> {
    let f = fixture().await?;
    let id = f.submit(TOKEN_A).await?;
    let agent = f.agent(&id)?;
    agent.stdout(b"hello\n").await?;
    agent.stdout(&[0xff, 0xfe, 0x00]).await?;
    agent.post(TTY_STDERR, b"oops").await?;

    let (status, body) = f
        .call("POST", &format!("/v1/jobs/{id}/attach"), Some(TOKEN_A), Some(json!({})))
        .await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["expires_in_s"], 30, "{body}");
    let url = body["stream_url"].as_str().context("stream_url")?;
    assert_eq!(
        url,
        format!("/v1/jobs/{id}/stream/{}", url.rsplit('/').next().context("ticket")?)
    );

    let resp = f.open_stream(url, Some(TOKEN_A)).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["content-type"], "application/x-ndjson");
    assert_eq!(resp.headers()["cache-control"], "no-store");
    let mut lines = Lines::new(resp);
    let got = lines.output_bytes(6 + 3 + 4).await?;
    assert_eq!(got, [b"hello\n".as_slice(), &[0xff, 0xfe, 0x00], b"oops"].concat());

    f.finish(&id, JobStatus::Succeeded)?;
    let last = tokio::time::timeout(WAIT, lines.last())
        .await
        .context("no exit line")??;
    assert_eq!(
        last,
        json!({"type": "exit", "reason": "job_terminal:JOB_STATUS_SUCCEEDED"})
    );
    Ok(())
}

#[tokio::test]
async fn an_attach_to_a_job_that_ends_with_no_output_exits_with_its_terminal_status() -> Result<()> {
    let f = fixture().await?;
    let id = f.submit(TOKEN_A).await?;
    let url = f.attach(&id, TOKEN_A).await?;
    let mut lines = Lines::new(f.open_stream(&url, Some(TOKEN_A)).await?);
    let (status, _) = f
        .call("POST", &format!("/v1/jobs/{id}/cancel"), Some(TOKEN_A), None)
        .await?;
    assert_eq!(status, StatusCode::OK);
    let last = tokio::time::timeout(WAIT, lines.last())
        .await
        .context("no exit line")??;
    assert_eq!(
        last,
        json!({"type": "exit", "reason": "job_terminal:JOB_STATUS_CANCELLED"})
    );
    Ok(())
}

#[tokio::test]
async fn another_client_cannot_attach_or_use_the_owners_stream_url() -> Result<()> {
    let f = fixture().await?;
    let id = f.submit(TOKEN_A).await?;
    let (unknown_status, unknown) = f
        .call("POST", "/v1/jobs/no-such-job/attach", Some(TOKEN_B), Some(json!({})))
        .await?;
    let (status, foreign) = f
        .call("POST", &format!("/v1/jobs/{id}/attach"), Some(TOKEN_B), Some(json!({})))
        .await?;
    assert_eq!((status, &foreign), (StatusCode::NOT_FOUND, &unknown));
    assert_eq!(
        (unknown_status, &foreign["code"]),
        (StatusCode::NOT_FOUND, &json!("not_found"))
    );

    let url = f.attach(&id, TOKEN_A).await?;
    let stolen = f.open_stream(&url, Some(TOKEN_B)).await?;
    assert_eq!(stolen.status(), StatusCode::NOT_FOUND);
    let stolen_body: Value = stolen.json().await?;
    let bogus = f
        .open_stream(&format!("/v1/jobs/{id}/stream/{}", "0".repeat(64)), Some(TOKEN_B))
        .await?;
    assert_eq!(
        stolen_body,
        bogus.json::<Value>().await?,
        "a stolen ticket must look unknown"
    );

    // The failed attempt did not burn the owner's ticket.
    let own = f.open_stream(&url, Some(TOKEN_A)).await?;
    assert_eq!(own.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn the_stream_requires_a_bearer() -> Result<()> {
    let f = fixture().await?;
    let id = f.submit(TOKEN_A).await?;
    let url = f.attach(&id, TOKEN_A).await?;
    for token in [None, Some("wrong-token")] {
        let resp = f.open_stream(&url, token).await?;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(resp.json::<Value>().await?["code"], "unauthenticated");
    }
    let own = f.open_stream(&url, Some(TOKEN_A)).await?;
    assert_eq!(
        own.status(),
        StatusCode::OK,
        "a refused bearer must not burn the ticket"
    );
    Ok(())
}

#[tokio::test]
async fn a_ticket_works_once() -> Result<()> {
    let f = fixture().await?;
    let id = f.submit(TOKEN_A).await?;
    let url = f.attach(&id, TOKEN_A).await?;
    let first = f.open_stream(&url, Some(TOKEN_A)).await?;
    assert_eq!(first.status(), StatusCode::OK);
    let second = f.open_stream(&url, Some(TOKEN_A)).await?;
    assert_eq!(second.status(), StatusCode::NOT_FOUND);
    assert_eq!(second.json::<Value>().await?["code"], "not_found");
    Ok(())
}

#[tokio::test]
async fn an_expired_ticket_is_not_found() -> Result<()> {
    let f = fixture_with_opts(Opts {
        ticket_ttl: Duration::from_millis(150),
        ..Opts::default()
    })
    .await?;
    let id = f.submit(TOKEN_A).await?;
    let url = f.attach(&id, TOKEN_A).await?;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let resp = f.open_stream(&url, Some(TOKEN_A)).await?;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn malformed_and_cross_job_tickets_are_not_found() -> Result<()> {
    let f = fixture().await?;
    let (one, other) = (f.submit(TOKEN_A).await?, f.submit(TOKEN_A).await?);
    let url = f.attach(&one, TOKEN_A).await?;
    let ticket = url.rsplit('/').next().context("ticket")?.to_owned();
    for bad in ["not-a-ticket", &"g".repeat(64), &"0".repeat(63), &ticket.to_uppercase()] {
        let resp = f
            .open_stream(&format!("/v1/jobs/{one}/stream/{bad}"), Some(TOKEN_A))
            .await?;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "ticket {bad:?}");
    }
    let wrong_job = f
        .open_stream(&format!("/v1/jobs/{other}/stream/{ticket}"), Some(TOKEN_A))
        .await?;
    assert_eq!(
        wrong_job.status(),
        StatusCode::NOT_FOUND,
        "a ticket is bound to its job"
    );
    let right = f.open_stream(&url, Some(TOKEN_A)).await?;
    assert_eq!(
        right.status(),
        StatusCode::OK,
        "refused attempts must not burn the ticket"
    );
    Ok(())
}

#[tokio::test]
async fn a_dropped_client_leaves_the_job_running_and_it_can_be_attached_again() -> Result<()> {
    let f = fixture().await?;
    let id = f.submit(TOKEN_A).await?;
    let agent = f.agent(&id)?;
    agent.stdout(b"first").await?;
    let url = f.attach(&id, TOKEN_A).await?;
    let mut lines = Lines::new(f.open_stream(&url, Some(TOKEN_A)).await?);
    assert_eq!(lines.output_bytes(5).await?, b"first");
    drop(lines);

    let (_, got) = f.call("GET", &format!("/v1/jobs/{id}"), Some(TOKEN_A), None).await?;
    assert_eq!(got["state"], "pending", "a dropped stream must not touch the job");
    agent.stdout(b"second").await?;
    let again = f.attach(&id, TOKEN_A).await?;
    let mut lines = Lines::new(f.open_stream(&again, Some(TOKEN_A)).await?);
    // Replay from the start is accepted: the new stream sees everything.
    assert_eq!(lines.output_bytes(11).await?, b"firstsecond");
    Ok(())
}

#[tokio::test]
async fn a_client_holds_at_most_four_tickets_and_streams_and_a_closed_stream_frees_its_slot() -> Result<()> {
    let f = fixture().await?;
    let id = f.submit(TOKEN_A).await?;
    let mut urls = Vec::new();
    for _ in 0..4 {
        urls.push(f.attach(&id, TOKEN_A).await?);
    }
    let (status, body) = f
        .call("POST", &format!("/v1/jobs/{id}/attach"), Some(TOKEN_A), Some(json!({})))
        .await?;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::TOO_MANY_REQUESTS, &json!("quota_exceeded")),
        "{body}"
    );

    // Redeeming a ticket turns it into a live stream, so the slot stays taken.
    let live = f.open_stream(&urls[0], Some(TOKEN_A)).await?;
    assert_eq!(live.status(), StatusCode::OK);
    let (status, _) = f
        .call("POST", &format!("/v1/jobs/{id}/attach"), Some(TOKEN_A), Some(json!({})))
        .await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);

    // Closing the stream frees it.
    drop(live);
    let mut freed = false;
    for _ in 0..50 {
        let (status, _) = f
            .call("POST", &format!("/v1/jobs/{id}/attach"), Some(TOKEN_A), Some(json!({})))
            .await?;
        if status == StatusCode::OK {
            freed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(freed, "a closed stream never released its slot");
    Ok(())
}

#[tokio::test]
async fn a_job_sandyd_cannot_join_gives_unavailable_and_leaves_no_ticket() -> Result<()> {
    let f = fixture_with_opts(Opts {
        attach_socket: false,
        ..Opts::default()
    })
    .await?;
    let id = f.submit(TOKEN_A).await?;
    let url = f.attach(&id, TOKEN_A).await?;
    let first = f.open_stream(&url, Some(TOKEN_A)).await?;
    assert_eq!(first.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = first.json().await?;
    assert_eq!(body["code"], "unavailable");
    let second = f.open_stream(&url, Some(TOKEN_A)).await?;
    assert_eq!(
        second.status(),
        StatusCode::NOT_FOUND,
        "a failed join must still consume the ticket"
    );
    Ok(())
}

#[tokio::test]
async fn a_finished_job_cannot_be_attached() -> Result<()> {
    let f = fixture().await?;
    let id = f.submit(TOKEN_A).await?;
    f.finish(&id, JobStatus::Failed)?;
    let (status, body) = f
        .call("POST", &format!("/v1/jobs/{id}/attach"), Some(TOKEN_A), Some(json!({})))
        .await?;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::SERVICE_UNAVAILABLE, &json!("unavailable")),
        "{body}"
    );
    Ok(())
}

const BIG_CHUNKS: usize = 64;
const BIG_CHUNK: usize = 64 * 1024;

#[tokio::test]
async fn a_job_finished_before_the_stream_opens_still_delivers_every_byte_to_a_slow_reader() -> Result<()> {
    let f = fixture().await?;
    let id = f.submit(TOKEN_A).await?;
    let agent = f.agent(&id)?;
    for n in 0..BIG_CHUNKS {
        agent.stdout(&vec![u8::try_from(n)?; BIG_CHUNK]).await?;
    }
    let url = f.attach(&id, TOKEN_A).await?;
    f.finish(&id, JobStatus::Succeeded)?;
    let resp = f.open_stream(&url, Some(TOKEN_A)).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    // Longer than any fixed drain window: the replay has to wait on this reader.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let mut lines = Lines::new(resp);
    let got = lines.output_bytes(BIG_CHUNKS * BIG_CHUNK).await?;
    assert_eq!(got.len(), BIG_CHUNKS * BIG_CHUNK);
    for (n, chunk) in got.chunks(BIG_CHUNK).enumerate() {
        assert!(chunk.iter().all(|b| usize::from(*b) == n), "chunk {n} is wrong");
    }
    let last = tokio::time::timeout(WAIT, lines.last())
        .await
        .context("no exit line")??;
    assert_eq!(
        last,
        json!({"type": "exit", "reason": "job_terminal:JOB_STATUS_SUCCEEDED"})
    );
    Ok(())
}

#[tokio::test]
async fn a_client_that_stops_reading_frees_its_slot_within_the_send_timeout() -> Result<()> {
    let f = fixture_with_opts(Opts {
        send_timeout: Duration::from_millis(300),
        ..Opts::default()
    })
    .await?;
    let id = f.submit(TOKEN_A).await?;
    let agent = f.agent(&id)?;
    for _ in 0..BIG_CHUNKS {
        agent.stdout(&vec![7_u8; BIG_CHUNK]).await?;
    }
    // Three idle tickets leave one slot: the stream's own.
    let mut spare = Vec::new();
    for _ in 0..3 {
        spare.push(f.attach(&id, TOKEN_A).await?);
    }
    let url = f.attach(&id, TOKEN_A).await.context("the fourth slot")?;
    // Hold the response open and never read it.
    let stalled = f.open_stream(&url, Some(TOKEN_A)).await?;
    assert_eq!(stalled.status(), StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut freed = false;
    for _ in 0..50 {
        let (status, _) = f
            .call("POST", &format!("/v1/jobs/{id}/attach"), Some(TOKEN_A), Some(json!({})))
            .await?;
        if status == StatusCode::OK {
            freed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(freed, "a stalled reader pinned its stream slot");
    drop(stalled);
    Ok(())
}
