//! Spawning a run's launch command as the leader of a new process group, with
//! its stdout and stderr piped and the given stdin (#281).
//!
//! Linux spawns through std (via command-group): every descriptor std and sandy
//! create there is close-on-exec atomically. On Apple a socket or pipe gets
//! close-on-exec in a second call, so a descriptor another thread is creating
//! can leak into any spawn. There the child is spawned with `posix_spawn` and
//! `POSIX_SPAWN_CLOEXEC_DEFAULT`, which closes everything except the three stdio
//! descriptors mapped onto 0, 1 and 2. The command's argv, env and PATH lookup
//! come from the same `Command`, so the two paths cannot drift apart.

use std::{
    fs::File,
    io,
    os::fd::OwnedFd,
    process::{Command, ExitStatus},
};

/// A spawned run: the leader of its own process group.
pub(crate) struct JobChild(Inner);

enum Inner {
    #[cfg(not(target_vendor = "apple"))]
    Group(command_group::GroupChild),
    #[cfg(target_vendor = "apple")]
    Spawned(apple::Spawned),
}

/// Spawn `command` as a new process-group leader, with `stdin` (or `/dev/null`)
/// on fd 0 and its stdout and stderr piped back.
pub(crate) fn spawn_job(command: Command, stdin: Option<OwnedFd>) -> io::Result<JobChild> {
    #[cfg(not(target_vendor = "apple"))]
    {
        use std::process::Stdio;

        use command_group::CommandGroup;
        let mut command = command;
        command
            .stdin(stdin.map_or_else(Stdio::null, Stdio::from))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        Ok(JobChild(Inner::Group(command.group_spawn()?)))
    }
    #[cfg(target_vendor = "apple")]
    {
        Ok(JobChild(Inner::Spawned(apple::spawn(&command, stdin)?)))
    }
}

impl JobChild {
    /// The child's pid, which is also its process group id.
    pub(crate) fn id(&self) -> u32 {
        match &self.0 {
            #[cfg(not(target_vendor = "apple"))]
            Inner::Group(child) => child.id(),
            #[cfg(target_vendor = "apple")]
            Inner::Spawned(child) => child.id(),
        }
    }

    /// The read end of the child's stdout, once.
    pub(crate) fn take_stdout(&mut self) -> Option<File> {
        match &mut self.0 {
            #[cfg(not(target_vendor = "apple"))]
            Inner::Group(child) => child.inner().stdout.take().map(|out| File::from(OwnedFd::from(out))),
            #[cfg(target_vendor = "apple")]
            Inner::Spawned(child) => child.stdout.take(),
        }
    }

    /// The read end of the child's stderr, once.
    pub(crate) fn take_stderr(&mut self) -> Option<File> {
        match &mut self.0 {
            #[cfg(not(target_vendor = "apple"))]
            Inner::Group(child) => child.inner().stderr.take().map(|err| File::from(OwnedFd::from(err))),
            #[cfg(target_vendor = "apple")]
            Inner::Spawned(child) => child.stderr.take(),
        }
    }

    /// The exit status if the leader has exited, without blocking.
    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        match &mut self.0 {
            #[cfg(not(target_vendor = "apple"))]
            Inner::Group(child) => child.try_wait(),
            #[cfg(target_vendor = "apple")]
            Inner::Spawned(child) => child.try_wait(),
        }
    }

    /// Wait for the leader to exit.
    pub(crate) fn wait(&mut self) -> io::Result<ExitStatus> {
        match &mut self.0 {
            #[cfg(not(target_vendor = "apple"))]
            Inner::Group(child) => child.wait(),
            #[cfg(target_vendor = "apple")]
            Inner::Spawned(child) => child.wait(),
        }
    }

    /// SIGKILL the whole process group.
    pub(crate) fn kill(&mut self) -> io::Result<()> {
        match &mut self.0 {
            #[cfg(not(target_vendor = "apple"))]
            Inner::Group(child) => child.kill(),
            #[cfg(target_vendor = "apple")]
            Inner::Spawned(child) => child.kill(),
        }
    }
}

#[cfg(target_vendor = "apple")]
mod apple {
    use std::{
        ffi::{CString, OsStr},
        fs::File,
        io,
        os::{
            fd::{AsFd, AsRawFd, OwnedFd},
            unix::{ffi::OsStrExt, fs::PermissionsExt, process::ExitStatusExt},
        },
        path::{Path, PathBuf},
        process::{Command, ExitStatus},
    };

    use nix::{
        spawn::{PosixSpawnAttr, PosixSpawnFileActions, PosixSpawnFlags, posix_spawn},
        sys::signal::{SigSet, Signal as NixSignal},
        unistd::Pid as NixPid,
    };
    use rustix::{
        fs::{Mode, OFlags},
        io::{FdFlags, fcntl_dupfd_cloexec, fcntl_setfd},
        process::{Pid, Signal, WaitOptions, kill_process_group, waitpid},
    };

    pub(super) struct Spawned {
        pid: Pid,
        status: Option<ExitStatus>,
        pub(super) stdout: Option<File>,
        pub(super) stderr: Option<File>,
    }

    pub(super) fn spawn(command: &Command, stdin: Option<OwnedFd>) -> io::Result<Spawned> {
        let program = c_string(command.get_program().as_bytes())?;
        let argv = std::iter::once(Ok(program))
            .chain(command.get_args().map(|arg| c_string(arg.as_bytes())))
            .collect::<io::Result<Vec<_>>>()?;
        // The env is exactly what the command sets: it was env_clear()ed, so a
        // removed or unset variable is simply absent.
        let envp = command
            .get_envs()
            .filter_map(|(key, value)| value.map(|value| c_string(&[key.as_bytes(), b"=", value.as_bytes()].concat())))
            .collect::<io::Result<Vec<_>>>()?;

        let stdin = match stdin {
            Some(fd) => fd,
            None => rustix::fs::open("/dev/null", OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())?,
        };
        let (out_read, out_write) = rustix::pipe::pipe()?;
        let (err_read, err_write) = rustix::pipe::pipe()?;
        for fd in [&out_read, &out_write, &err_read, &err_write] {
            // Ours stay out of any std spawn elsewhere; the child gets its copies
            // only through the dup2s below.
            fcntl_setfd(fd, FdFlags::CLOEXEC)?;
        }
        // A dup2 onto the same number is a no-op that keeps close-on-exec, and
        // CLOEXEC_DEFAULT would then close it in the child: map from above 2.
        let (stdin, out_write, err_write) = (above_stdio(stdin)?, above_stdio(out_write)?, above_stdio(err_write)?);

        let mut actions = PosixSpawnFileActions::init()?;
        actions.add_dup2(stdin.as_raw_fd(), 0)?;
        actions.add_dup2(out_write.as_raw_fd(), 1)?;
        actions.add_dup2(err_write.as_raw_fd(), 2)?;

        let mut attr = PosixSpawnAttr::init()?;
        // POSIX_SPAWN_CLOEXEC_DEFAULT is Apple-only and nix does not model it,
        // so it is passed through as a raw bit; do not drop it, it is the point
        // of this path (#281). 0x4000 | the others fits the positive range of
        // the c_short that posix_spawnattr_setflags takes.
        attr.set_flags(
            PosixSpawnFlags::from_bits_retain(nix::libc::POSIX_SPAWN_CLOEXEC_DEFAULT)
                | PosixSpawnFlags::POSIX_SPAWN_SETPGROUP
                | PosixSpawnFlags::POSIX_SPAWN_SETSIGDEF,
        )?;
        // A new group led by the child, as command-group's process_group(0).
        attr.set_pgroup(NixPid::from_raw(0))?;
        // As std does: SIGPIPE back to default (Rust ignores it in this process);
        // the signal mask is inherited.
        let mut default_signals = SigSet::empty();
        default_signals.add(NixSignal::SIGPIPE);
        attr.set_sigdefault(&default_signals)?;

        // Look a bare name up on the job's PATH, as std does (via execvp in the
        // child), never on this process's: spec.env may override PATH.
        let job_path = command
            .get_envs()
            .filter(|(key, _)| *key == "PATH")
            .last()
            .and_then(|(_, value)| value);
        let executable = resolve(command.get_program(), job_path)?;
        let pid = posix_spawn(executable.as_path(), &actions, &attr, &argv, &envp)?;
        drop((stdin, out_write, err_write));
        let pid = Pid::from_raw(pid.as_raw()).ok_or_else(|| io::Error::other("posix_spawn returned pid 0"))?;
        Ok(Spawned {
            pid,
            status: None,
            stdout: Some(File::from(out_read)),
            stderr: Some(File::from(err_read)),
        })
    }

    /// `program` itself if it names a path, else the first executable regular
    /// file on `path` as execvp searches it (an empty entry is the current dir;
    /// no PATH means the system default). Not found is `NotFound`, as std reports.
    fn resolve(program: &OsStr, path: Option<&OsStr>) -> io::Result<PathBuf> {
        if program.as_bytes().contains(&b'/') {
            return Ok(PathBuf::from(program));
        }
        let path = path.unwrap_or(OsStr::new("/usr/bin:/bin"));
        path.as_bytes()
            .split(|&b| b == b':')
            .map(|dir| match dir {
                b"" => Path::new(".").join(program),
                dir => Path::new(OsStr::from_bytes(dir)).join(program),
            })
            .find(|candidate| {
                std::fs::metadata(candidate).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
            })
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }

    fn c_string(bytes: &[u8]) -> io::Result<CString> {
        CString::new(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
    }

    /// `fd` itself if it is above 2, else a close-on-exec duplicate that is.
    fn above_stdio(fd: OwnedFd) -> io::Result<OwnedFd> {
        if fd.as_raw_fd() > 2 {
            return Ok(fd);
        }
        Ok(fcntl_dupfd_cloexec(fd.as_fd(), 3)?)
    }

    impl Spawned {
        pub(super) fn id(&self) -> u32 {
            self.pid.as_raw_pid().unsigned_abs()
        }

        pub(super) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
            if self.status.is_none()
                && let Some((_, status)) = waitpid(Some(self.pid), WaitOptions::NOHANG)?
            {
                self.status = Some(ExitStatus::from_raw(status.as_raw()));
            }
            Ok(self.status)
        }

        pub(super) fn wait(&mut self) -> io::Result<ExitStatus> {
            loop {
                if let Some(status) = self.status {
                    return Ok(status);
                }
                match waitpid(Some(self.pid), WaitOptions::empty()) {
                    Ok(Some((_, status))) => self.status = Some(ExitStatus::from_raw(status.as_raw())),
                    Ok(None) => {}
                    Err(rustix::io::Errno::INTR) => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }

        pub(super) fn kill(&mut self) -> io::Result<()> {
            Ok(kill_process_group(self.pid, Signal::KILL)?)
        }
    }
}
