//! Established client connections to a local TCP port, for the idle-stop lease (#645).
//!
//! Linux reads `/proc/net/tcp` and `/proc/net/tcp6`; other Unix hosts parse `netstat -an -p tcp`.
//! Only sockets whose local port is the service port count, so the service's own outbound
//! connections never read as use.

use std::process::Command;

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
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("read {table}: {e}")),
            }
        }
        Ok(total)
    } else {
        let out = Command::new("netstat")
            .args(["-an", "-p", "tcp"])
            .output()
            .map_err(|e| format!("run netstat: {e}"))?;
        if !out.status.success() {
            return Err(format!("netstat exited with {}", out.status));
        }
        Ok(count_netstat(&String::from_utf8_lossy(&out.stdout), port))
    }
}

/// Counts `ESTABLISHED` rows (state `01`) of a `/proc/net/tcp{,6}` table with local port `port`.
fn count_proc_net_tcp(text: &str, port: u16) -> usize {
    let _ = (text, port);
    0
}

/// Counts `ESTABLISHED` rows of BSD `netstat -an` output with local port `port`.
fn count_netstat(text: &str, port: u16) -> usize {
    let _ = (text, port);
    0
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
