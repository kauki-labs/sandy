//! A stand-in for `t3 serve` and `t3 pair`, used by the tests.
//!
//! `fake-t3 serve --port P --base-dir D [--ready-after-ms N] [--exit-after-ms N]
//! [--child-beat-file F] [--split-status] [--dump-env]` answers `503` until N ms after start and `200`
//! after, optionally exits on its own, optionally starts a child that beats into
//! the file F (outside the environment directory, so a test can tell a live child
//! from a removed directory), and optionally writes its environment to `D/env.txt`.
//! `fake-t3 pair --base-dir D [--fail]` prints a pairing code (or fails).
//! `fake-t3 pair-hang [--beat-file F]` starts a beating child and then hangs.
//! `fake-t3 beat --file F` rewrites F with a counter every 20 ms.

use std::{
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    process::{Command, ExitCode},
    time::{Duration, Instant},
};

const PAIRING_CODE: &str = "PAIRCANARY-7d3f9a1c";

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("serve") => serve(&args),
        Some("pair") => {
            if has(&args, "--fail") {
                eprintln!("{PAIRING_CODE} could not be minted");
                return ExitCode::from(1);
            }
            println!("{PAIRING_CODE}");
            ExitCode::SUCCESS
        }
        Some("beat") => beat(&args),
        Some("pair-hang") => {
            if let Some(file) = flag(&args, "--beat-file") {
                let me = std::env::current_exe().unwrap_or_default();
                let _ = Command::new(me).arg("beat").arg("--file").arg(file).spawn();
            }
            loop {
                std::thread::sleep(Duration::from_secs(60));
            }
        }
        _ => ExitCode::from(2),
    }
}

fn beat(args: &[String]) -> ExitCode {
    let Some(file) = flag(args, "--file") else {
        return ExitCode::from(2);
    };
    let mut n: u64 = 0;
    loop {
        n += 1;
        let _ = std::fs::write(&file, n.to_string());
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn serve(args: &[String]) -> ExitCode {
    let (Some(port), Some(dir)) = (flag(args, "--port"), flag(args, "--base-dir")) else {
        return ExitCode::from(2);
    };
    let dir = PathBuf::from(dir);
    let ready_after = Duration::from_millis(flag(args, "--ready-after-ms").and_then(|v| v.parse().ok()).unwrap_or(0));
    let exit_after = flag(args, "--exit-after-ms")
        .and_then(|v| v.parse().ok())
        .map(Duration::from_millis);
    if has(args, "--dump-env") {
        let env: String = std::env::vars().map(|(k, v)| format!("{k}={v}\n")).collect();
        let _ = std::fs::write(dir.join("env.txt"), env);
    }
    if let Some(file) = flag(args, "--child-beat-file") {
        let me = std::env::current_exe().unwrap_or_default();
        let _ = Command::new(me).arg("beat").arg("--file").arg(file).spawn();
    }
    let split_status = has(args, "--split-status");
    let Ok(listener) = TcpListener::bind(format!("127.0.0.1:{port}")) else {
        return ExitCode::from(3);
    };
    let _ = listener.set_nonblocking(true);
    let started = Instant::now();
    loop {
        if exit_after.is_some_and(|d| started.elapsed() >= d) {
            return ExitCode::from(7);
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                let mut buf = [0u8; 512];
                let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                let _ = stream.read(&mut buf);
                let status = if started.elapsed() >= ready_after {
                    "200 OK"
                } else {
                    "503 Service Unavailable"
                };
                if split_status {
                    let _ = stream.write_all(b"HTTP/1.");
                    let _ = stream.flush();
                    std::thread::sleep(Duration::from_millis(150));
                    let _ = write!(stream, "1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                } else {
                    let _ = write!(
                        stream,
                        "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                }
            }
            Err(_) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}
