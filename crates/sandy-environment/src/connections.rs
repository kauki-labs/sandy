//! Established client connections to a local TCP port, for the idle-stop lease (#645), and who listens on it (#637).
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

/// Who holds the listening socket on a service's port.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Holder {
    /// Nothing that a dial to 127.0.0.1 reaches listens on the port yet.
    Nobody,
    /// Every listener a dial to 127.0.0.1 can reach belongs to the launched process group.
    Group,
    /// Some such listener is not the group's: another process took the port, or shares it.
    Other,
}

/// Who listens on the port, as a client dialing 127.0.0.1 would see it, from process group `pgid` (the service's;
/// its leader's pid is `pgid`). Only listeners that dial can reach count (bound to 127.0.0.1 or to a wildcard), so a
/// stranger on another address does not read as holding the service's port, and every such listener must be the
/// group's, so a stranger sharing the port (`SO_REUSEPORT`) is caught.
///
/// Linux joins the listening sockets' inodes in `/proc/net/tcp{,6}` to the `socket:[inode]` links under
/// `/proc/<pid>/fd` of the group's processes. Other Unix hosts ask `/usr/sbin/lsof` for the listeners' pids and read
/// their process groups with `/bin/ps`. A listener `lsof` cannot see (another user's) reads as [`Holder::Nobody`], so
/// it is never taken for the service.
///
/// # Errors
/// The text of the failure when the host's socket or process tables cannot be read. The caller retries: a table that
/// cannot be read is not evidence that the port belongs to a stranger.
pub(crate) fn listener_holder(port: u16, pgid: i32) -> Result<Holder, String> {
    if cfg!(target_os = "linux") {
        let mut inodes = Vec::new();
        for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
            match std::fs::read_to_string(table) {
                Ok(text) => inodes.extend(listening_inodes(&text, port)),
                Err(e) if table.ends_with("tcp6") && e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("read {table}: {e}")),
            }
        }
        if inodes.is_empty() {
            return Ok(Holder::Nobody);
        }
        Ok(if group_holds_all(pgid, &inodes)? {
            Holder::Group
        } else {
            Holder::Other
        })
    } else {
        let out = match run_bounded(
            Command::new("/usr/sbin/lsof").args(["-nP", "-a", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-Fpn"]),
            NETSTAT_TIMEOUT,
        ) {
            Ok(out) => out,
            // `lsof` exits 1 when it finds nothing.
            Err(e) if e.contains("exited with exit status: 1") => return Ok(Holder::Nobody),
            Err(e) => return Err(e),
        };
        let pids = lsof_dialable_pids(&out);
        if pids.is_empty() {
            return Ok(Holder::Nobody);
        }
        let list = pids.iter().map(i32::to_string).collect::<Vec<_>>().join(",");
        // A listener that exited since `lsof` ran is gone: ask again on the next probe.
        let Ok(rows) = run_bounded(
            Command::new("/bin/ps").args(["-o", "pid=,pgid=", "-p", &list]),
            NETSTAT_TIMEOUT,
        ) else {
            return Ok(Holder::Nobody);
        };
        let groups = ps_groups(&rows);
        Ok(
            if pids
                .iter()
                .all(|pid| groups.iter().any(|(p, g)| p == pid && *g == pgid))
            {
                Holder::Group
            } else {
                Holder::Other
            },
        )
    }
}

/// The pids of `lsof -Fpn` output whose listener a dial to 127.0.0.1 reaches: `n` names `127.0.0.1:P` or `*:P`.
fn lsof_dialable_pids(text: &str) -> Vec<i32> {
    let mut pids = Vec::new();
    let mut pid = None;
    for line in text.lines() {
        if let Some(p) = line.strip_prefix('p') {
            pid = p.parse().ok();
        } else if let Some(name) = line.strip_prefix('n')
            && (name.starts_with("127.0.0.1:") || name.starts_with("*:"))
            && let Some(pid) = pid
            && !pids.contains(&pid)
        {
            pids.push(pid);
        }
    }
    pids
}

/// `(pid, pgid)` pairs of `ps -o pid=,pgid=` output.
fn ps_groups(text: &str) -> Vec<(i32, i32)> {
    text.lines()
        .filter_map(|l| {
            let mut cols = l.split_whitespace();
            Some((cols.next()?.parse().ok()?, cols.next()?.parse().ok()?))
        })
        .collect()
}

/// Inodes of the listening sockets (state `0A`) in a `/proc/net/tcp{,6}` table with local port `port`, bound where a
/// dial to 127.0.0.1 arrives: `127.0.0.1`, the IPv4 or IPv6 wildcard, or the IPv4-mapped loopback.
fn listening_inodes(text: &str, port: u16) -> Vec<u64> {
    const DIALABLE: [&str; 4] = [
        "0100007F",
        "00000000",
        "00000000000000000000000000000000",
        "0000000000000000FFFF00000100007F",
    ];
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            let (addr, local_port) = cols.get(1)?.rsplit_once(':')?;
            if *cols.get(3)? != "0A"
                || u16::from_str_radix(local_port, 16).ok()? != port
                || !DIALABLE.contains(&addr.to_ascii_uppercase().as_str())
            {
                return None;
            }
            cols.get(9)?.parse().ok()
        })
        .collect()
}

/// Whether the processes of group `pgid` hold every one of the socket `inodes`.
///
/// # Errors
/// `/proc` or a group member's descriptor table cannot be read (a process that exited meanwhile is skipped), and an
/// inode is still unaccounted for: the unreadable table may hold it.
#[cfg(target_os = "linux")]
fn group_holds_all(pgid: i32, inodes: &[u64]) -> Result<bool, String> {
    let mut missing: Vec<String> = inodes.iter().map(|i| format!("socket:[{i}]")).collect();
    let mut unreadable = None;
    let procs = std::fs::read_dir("/proc").map_err(|e| format!("read /proc: {e}"))?;
    for entry in procs.flatten() {
        if !entry.file_name().to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        match process_stat(&entry.path().join("stat")) {
            // A dead process holds nothing, and its descriptor table is not readable.
            Some((state, group)) if group == pgid && !is_dead(state) => {}
            _ => continue,
        }
        match std::fs::read_dir(entry.path().join("fd")) {
            Ok(fds) => {
                for fd in fds.flatten() {
                    if let Ok(link) = std::fs::read_link(fd.path()) {
                        missing.retain(|w| link.as_os_str() != w.as_str());
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // The member may have died since its state was read: look again before calling the table unreadable.
            Err(_)
                if process_stat(&entry.path().join("stat"))
                    .is_none_or(|(state, group)| group != pgid || is_dead(state)) => {}
            Err(e) => unreadable = Some(format!("read {}: {e}", entry.path().join("fd").display())),
        }
    }
    match (missing.is_empty(), unreadable) {
        (true, _) => Ok(true),
        (false, None) => Ok(false),
        (false, Some(why)) => Err(why),
    }
}

#[cfg(not(target_os = "linux"))]
fn group_holds_all(_pgid: i32, _inodes: &[u64]) -> Result<bool, String> {
    Err("process descriptors are read on Linux only".to_owned())
}

/// The state letter and process group of a `/proc/<pid>/stat` file, or `None` when it is gone or unparsable.
#[cfg(target_os = "linux")]
fn process_stat(stat: &std::path::Path) -> Option<(char, i32)> {
    parse_stat(&std::fs::read_to_string(stat).ok()?)
}

/// A zombie (`Z`) or a process being removed (`X`).
#[cfg(target_os = "linux")]
fn is_dead(state: char) -> bool {
    matches!(state, 'Z' | 'X')
}

/// The state letter and process group in a `/proc/<pid>/stat` line: the fields after the command, which is in
/// parentheses and may itself hold spaces and parentheses. The state comes first, then the parent pid, then the group.
#[cfg(any(target_os = "linux", test))]
fn parse_stat(text: &str) -> Option<(char, i32)> {
    let mut fields = text.rsplit_once(')')?.1.split_whitespace();
    let state = fields.next()?.chars().next()?;
    let group = fields.nth(1)?.parse().ok()?;
    Some((state, group))
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
    fn only_listeners_a_dial_to_loopback_reaches_are_the_services() {
        const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111 1 0 100 0 0 10 0\n\
   1: 00000000:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 222 1 0 100 0 0 10 0\n\
   2: 0201A8C0:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 333 1 0 100 0 0 10 0\n\
   3: 0100007F:0CEA 0100007F:C000 01 00000000:00000000 00:00000000 00000000  1000        0 444 1 0 100 0 0 10 0\n\
   4: 0100007F:0CEB 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 555 1 0 100 0 0 10 0\n";
        const TCP6: &str = "  sl  local_address                         remote_address                        st \
                            tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n0: \
                            00000000000000000000000001000000:0CEA 00000000000000000000000000000000:0000 0A \
                            00000000:00000000 00:00000000 00000000  1000        0 666 1 0 100 0 0 10 0\n1: \
                            00000000000000000000000000000000:0CEA 00000000000000000000000000000000:0000 0A \
                            00000000:00000000 00:00000000 00000000  1000        0 777 1 0 100 0 0 10 0\n";
        // 0x0CEA is 3306. Loopback and the wildcard count; a LAN address, an established row, another port and
        // IPv6 `::1` (which a dial to 127.0.0.1 never reaches) do not.
        assert_eq!(listening_inodes(TCP, 3306), vec![111, 222]);
        assert_eq!(listening_inodes(TCP6, 3306), vec![777]);
        assert!(listening_inodes("", 3306).is_empty());
    }

    #[test]
    fn a_stat_line_names_its_state_and_group_even_when_the_command_holds_parentheses() {
        assert_eq!(parse_stat("4242 (fake-t3) S 1 4242 4242 0 -1"), Some(('S', 4242)));
        assert_eq!(parse_stat("4243 (a) b) c (d) Z 4242 4242 4242 0"), Some(('Z', 4242)));
        assert_eq!(parse_stat("garbage"), None);
    }

    #[test]
    fn lsof_output_yields_the_pids_of_listeners_a_dial_to_loopback_reaches() {
        let out = "p100\nf3\nn127.0.0.1:3000\np200\nf4\nn*:3000\nf5\nn*:3000\np300\nf6\nn[::1]:3000\np400\nf7\nn192.\
                   168.1.2:3000\n";
        assert_eq!(lsof_dialable_pids(out), vec![100, 200]);
        assert!(lsof_dialable_pids("").is_empty());
    }

    /// A group member that exited and is not reaped yet (a zombie) holds no descriptors and its `/proc/<pid>/fd` is
    /// not readable. That is a dead process, not a table that cannot be read: it holds nothing and is skipped (#637).
    #[cfg(target_os = "linux")]
    #[test]
    fn a_zombie_in_the_group_holds_nothing_and_is_not_an_error() -> anyhow::Result<()> {
        use std::os::unix::process::CommandExt;

        let mut child = Command::new("true").process_group(0).spawn()?;
        let pid = i32::try_from(child.id())?;
        let deadline = Instant::now() + Duration::from_secs(5);
        // `try_wait` would reap it: poll the state instead.
        while !std::fs::read_to_string(format!("/proc/{pid}/stat"))?
            .rsplit_once(')')
            .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z'))
        {
            anyhow::ensure!(Instant::now() < deadline, "the child never became a zombie");
            std::thread::sleep(Duration::from_millis(10));
        }
        let held = group_holds_all(pid, &[u64::MAX]);
        child.wait()?;
        assert_eq!(held, Ok(false), "a zombie holds no socket");
        Ok(())
    }

    #[test]
    fn ps_output_pairs_each_pid_with_its_process_group() {
        assert_eq!(ps_groups("  100   90\n 200  200\nbad\n"), vec![(100, 90), (200, 200)]);
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
