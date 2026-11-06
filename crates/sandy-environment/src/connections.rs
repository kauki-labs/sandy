//! Established client connections to a local TCP port, for the idle-stop lease (#645).
//!
//! Linux reads `/proc/net/tcp` and `/proc/net/tcp6`; other Unix hosts parse `/usr/sbin/netstat -an -p tcp` (an absolute
//! path, so a daemon with a minimal PATH still finds it). Only sockets whose local port is the service port count, so
//! the service's own outbound connections never read as use.

use std::{
    io::Read,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

/// The longest a `netstat` run may take. The driver's pass waits on it.
const NETSTAT_TIMEOUT: Duration = Duration::from_secs(5);

/// Number of established connections whose local port is `port`.
///
/// # Errors
/// The text of the failure when the host's socket table cannot be read.
pub(crate) fn established_to(port: u16) -> Result<usize, String> {
    if cfg!(target_os = "linux") {
        let mut total = 0;
        for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
            match std::fs::read_to_string(table) {
                Ok(text) => total += count_proc_net_tcp(&text, port),
                // An IPv6-less kernel has no tcp6 table.
                Err(e) if table.ends_with("tcp6") && e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("read {table}: {e}")),
            }
        }
        Ok(total)
    } else {
        let out = run_bounded(
            Command::new("/usr/sbin/netstat").args(["-an", "-p", "tcp"]),
            NETSTAT_TIMEOUT,
        )?;
        Ok(count_netstat(&out, port))
    }
}

/// Runs `cmd` and returns its stdout, killing and reaping it after `timeout`.
fn run_bounded(cmd: &mut Command, timeout: Duration) -> Result<String, String> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("run {:?}: {e}", cmd.get_program()))?;
    let mut stdout = child.stdout.take().ok_or("no stdout pipe")?;
    // A reader thread keeps a full pipe from blocking the child while we wait on it.
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stdout.read_to_string(&mut text);
        text
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{:?} timed out after {timeout:?}", cmd.get_program()));
            }
            Err(e) => return Err(format!("wait for {:?}: {e}", cmd.get_program())),
        }
    };
    let text = reader.join().map_err(|_| "reader thread panicked".to_owned())?;
    if status.success() {
        Ok(text)
    } else {
        Err(format!("{:?} exited with {status}", cmd.get_program()))
    }
}

/// Counts `ESTABLISHED` rows (state `01`) of a `/proc/net/tcp{,6}` table with local port `port`.
fn count_proc_net_tcp(text: &str, port: u16) -> usize {
    text.lines()
        .skip(1)
        .filter(|line| {
            let mut cols = line.split_whitespace();
            let (Some(local), Some(state)) = (cols.nth(1), cols.nth(1)) else {
                return false;
            };
            let local_port = local.rsplit_once(':').map(|(_, p)| p);
            state == "01" && local_port.and_then(|p| u16::from_str_radix(p, 16).ok()) == Some(port)
        })
        .count()
}

/// Counts `ESTABLISHED` rows of BSD `netstat -an` output with local port `port`.
fn count_netstat(text: &str, port: u16) -> usize {
    let suffix = format!(".{port}");
    text.lines()
        .filter(|line| line.starts_with("tcp") && line.trim_end().ends_with("ESTABLISHED"))
        .filter(|line| {
            line.split_whitespace()
                .nth(3)
                .is_some_and(|local| local.ends_with(&suffix))
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROC: &str =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: \
         0100007F:0ECD 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1 1 0\n   1: \
         0100007F:0ECD 0100007F:C350 01 00000000:00000000 00:00000000 00000000  1000        0 2 1 0\n   2: \
         0100007F:0ECD 0100007F:C351 01 00000000:00000000 00:00000000 00000000  1000        0 3 1 0\n   3: \
         0100007F:C350 0100007F:0ECD 01 00000000:00000000 00:00000000 00000000  1000        0 4 1 0\n   4: \
         0100007F:0ECD 0100007F:C352 06 00000000:00000000 00:00000000 00000000  1000        0 5 1 0\n";

    #[test]
    fn a_command_that_outlives_its_timeout_is_killed_and_reported() {
        let started = Instant::now();
        let err = run_bounded(Command::new("sleep").arg("30"), Duration::from_millis(200)).unwrap_err();
        assert!(err.contains("timed out"), "{err}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the child must be killed, not awaited"
        );
        assert_eq!(
            run_bounded(Command::new("echo").arg("hi"), Duration::from_secs(5)).as_deref(),
            Ok("hi\n")
        );
    }

    #[test]
    fn proc_rows_count_only_established_sockets_on_the_local_port() {
        // Rows 1 and 2 qualify. Row 0 listens, row 3 is the client end (remote port 0ECD), row 4 is TIME_WAIT.
        assert_eq!(count_proc_net_tcp(PROC, 0x0ECD), 2);
        assert_eq!(
            count_proc_net_tcp(PROC, 0xC350),
            1,
            "a different local port counts on its own"
        );
        assert_eq!(count_proc_net_tcp(PROC, 80), 0);
        assert_eq!(count_proc_net_tcp("", 0x0ECD), 0, "an empty table has no connections");
    }

    const NETSTAT: &str = "Active Internet connections (including servers)\n\
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)\n\
tcp4       0      0  127.0.0.1.3773         127.0.0.1.50000        ESTABLISHED\n\
tcp4       0      0  127.0.0.1.50000        127.0.0.1.3773         ESTABLISHED\n\
tcp46      0      0  *.3773                 *.*                    LISTEN\n\
tcp6       0      0  ::1.3773               ::1.50001              ESTABLISHED\n\
tcp4       0      0  127.0.0.1.3773         127.0.0.1.50002        TIME_WAIT\n\
tcp4       0      0  127.0.0.1.13773        127.0.0.1.50003        ESTABLISHED\n";

    #[test]
    fn netstat_rows_count_only_established_sockets_on_the_local_port() {
        // The IPv4 and IPv6 server-side rows qualify. The client end, the listener, TIME_WAIT
        // and a port that only ends in the digits (13773) do not.
        assert_eq!(count_netstat(NETSTAT, 3773), 2);
        assert_eq!(count_netstat(NETSTAT, 50000), 1);
        assert_eq!(count_netstat("", 3773), 0);
    }
}
