//! Who has a file open, and who started them: what `verrou env mount` shows
//! the user in the approval ("`cat` ← `zsh` ← `Terminal`") and uses to tell a
//! person's terminal from a coding agent.
//!
//! A file is identified by its device and inode, never by a path: the
//! holders of the writer's own descriptor are looked for, so that a name that
//! was swapped, linked or retired means nothing. macOS asks the kernel
//! through `libproc` (every process, every descriptor, the vnode behind it);
//! Linux reads `/proc`. Anywhere else nothing is known, and a read by an
//! unknown process is approved on its own, every time ([`crate::env`]).

use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use nix::errno::Errno;
use nix::sys::signal::kill;
use nix::unistd::Pid;

/// The device and inode of a file.
pub type Identity = (u64, u64);

/// The identity of a file from its metadata. macOS device numbers are 32
/// bits wide (the kernel's list of descriptors says so), whatever a `stat`
/// widens them to.
pub fn identity_of(meta: &std::fs::Metadata) -> Identity {
    (normal_device(meta.dev()), meta.ino())
}

#[cfg(target_os = "macos")]
fn normal_device(dev: u64) -> u64 {
    dev & 0xFFFF_FFFF
}

#[cfg(not(target_os = "macos"))]
fn normal_device(dev: u64) -> u64 {
    dev
}

/// What is known about the processes of this machine.
pub trait Processes: Send + Sync {
    /// The processes that have this file open now (this one excluded):
    /// found by the file's identity, not by a name.
    fn holders(&self, file: Identity) -> Vec<u32>;
    /// A process's parent; `None` if it is gone or unknown.
    fn parent(&self, pid: u32) -> Option<u32>;
    /// The path of a process's program; `None` if it is gone or unknown.
    fn exe(&self, pid: u32) -> Option<String>;
    /// A process's command line as one text, to see which script a
    /// JavaScript or Python runtime was given; `None` if unknown.
    fn args(&self, pid: u32) -> Option<String>;
    /// The terminal a process is attached to, as a number; `None` if it has
    /// none or it is unknown.
    fn tty(&self, pid: u32) -> Option<String>;
    /// When the process started, in a unit of the system's own: only ever
    /// compared with itself, to tell a process from a later one that got
    /// the same identifier.
    fn start_time(&self, pid: u32) -> Option<u64>;
}

/// The real thing.
pub struct System;

/// Is a process with this identifier running? One that belongs to someone
/// else counts: we cannot signal it, but it is there.
pub fn alive(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    pid > 1 && matches!(kill(Pid::from_raw(pid), None), Ok(()) | Err(Errno::EPERM))
}

/// The last component of a program's path.
pub fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Is this process the `verrou` that started at `start` (when the record
/// says so)? A reused identifier belongs to another program, and that one
/// must never be signalled.
pub fn is_verrou(procs: &dyn Processes, pid: u32, start: Option<u64>) -> bool {
    alive(pid)
        && procs
            .exe(pid)
            .is_some_and(|exe| basename(&exe).starts_with("verrou"))
        && start.is_none_or(|start| procs.start_time(pid) == Some(start))
}

/// `ps` for the command line of a process (macOS has no `/proc`, and its
/// own interface for it is out of reach without unsafe code).
#[cfg(not(target_os = "linux"))]
fn command_line_by_ps(pid: u32) -> Option<String> {
    let output = std::process::Command::new("/bin/ps")
        .args(["-ww", "-o", "args=", "-p", &pid.to_string()])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|text| !text.is_empty())
}

/// [`command_line_by_ps`] for a process that is the same one before and after
/// the question: `ps` takes a moment, and an identifier that was reused by
/// another program meanwhile would give that program's command line.
#[cfg(not(target_os = "linux"))]
fn checked_command_line(
    procs: &dyn Processes,
    pid: u32,
    ask: impl Fn(u32) -> Option<String>,
) -> Option<String> {
    let before = procs.start_time(pid);
    let text = ask(pid)?;
    (procs.start_time(pid) == before).then_some(text)
}

// MARK: macOS

/// `struct vnode_fdinfo` of `<sys/proc_info.h>`: what the kernel says of a
/// descriptor that is a file. libproc 0.14 has no type for it, but lets
/// one be described (and does the system call): only the layout is ours,
/// checked against a real descriptor in the tests.
#[cfg(target_os = "macos")]
mod vnode {
    use libproc::file_info::{PIDFDInfo, PIDFDInfoFlavor};

    #[repr(C)]
    #[derive(Default)]
    pub struct FileInfo {
        pub open_flags: u32,
        pub status: u32,
        pub offset: i64,
        pub kind: i32,
        pub guard_flags: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct Stat {
        pub dev: u32,
        pub mode: u16,
        pub nlink: u16,
        pub ino: u64,
        pub uid: u32,
        pub gid: u32,
        pub times: [i64; 8],
        pub size: i64,
        pub blocks: i64,
        pub blksize: i32,
        pub flags: u32,
        pub gen_number: u32,
        pub rdev: u32,
        pub spare: [i64; 2],
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct VnodeInfo {
        pub stat: Stat,
        pub kind: i32,
        pub pad: i32,
        pub fsid: [i32; 2],
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct VnodeFdInfo {
        pub file: FileInfo,
        pub vnode: VnodeInfo,
    }

    impl PIDFDInfo for VnodeFdInfo {
        fn flavor() -> PIDFDInfoFlavor {
            PIDFDInfoFlavor::VNodeInfo
        }
    }
}

/// The device and inode of every file a process has open.
#[cfg(target_os = "macos")]
fn open_files(pid: i32) -> Vec<Identity> {
    use libproc::bsd_info::BSDInfo;
    use libproc::file_info::{ListFDs, ProcFDType, pidfdinfo};
    use libproc::proc_pid::{listpidinfo, pidinfo};
    let Ok(info) = pidinfo::<BSDInfo>(pid, 0) else {
        return Vec::new();
    };
    // Room for descriptors opened since the count was made.
    let room = info.pbi_nfiles as usize + 32;
    let Ok(descriptors) = listpidinfo::<ListFDs>(pid, room) else {
        return Vec::new();
    };
    descriptors
        .iter()
        .filter(|d| matches!(ProcFDType::from(d.proc_fdtype), ProcFDType::VNode))
        .filter_map(|d| pidfdinfo::<vnode::VnodeFdInfo>(pid, d.proc_fd).ok())
        .map(|info| (u64::from(info.vnode.stat.dev), info.vnode.stat.ino))
        .collect()
}

#[cfg(target_os = "macos")]
impl Processes for System {
    fn holders(&self, file: Identity) -> Vec<u32> {
        use libproc::processes::{ProcFilter, pids_by_type};
        let own = std::process::id();
        let mut found: Vec<u32> = pids_by_type(ProcFilter::All)
            .unwrap_or_default()
            .into_iter()
            .filter(|pid| *pid != own && *pid > 0)
            .filter(|pid| i32::try_from(*pid).is_ok_and(|pid| open_files(pid).contains(&file)))
            .collect();
        found.sort_unstable();
        found
    }

    fn parent(&self, pid: u32) -> Option<u32> {
        let pid = i32::try_from(pid).ok()?;
        libproc::proc_pid::pidinfo::<libproc::bsd_info::BSDInfo>(pid, 0)
            .ok()
            .map(|info| info.pbi_ppid)
    }

    fn exe(&self, pid: u32) -> Option<String> {
        libproc::proc_pid::pidpath(i32::try_from(pid).ok()?).ok()
    }

    fn args(&self, pid: u32) -> Option<String> {
        checked_command_line(self, pid, command_line_by_ps)
    }

    fn tty(&self, pid: u32) -> Option<String> {
        let info =
            libproc::proc_pid::pidinfo::<libproc::bsd_info::BSDInfo>(i32::try_from(pid).ok()?, 0)
                .ok()?;
        // The kernel's "no terminal" is all ones.
        (info.e_tdev != u32::MAX && info.e_tdev != 0).then(|| info.e_tdev.to_string())
    }

    fn start_time(&self, pid: u32) -> Option<u64> {
        let info =
            libproc::proc_pid::pidinfo::<libproc::bsd_info::BSDInfo>(i32::try_from(pid).ok()?, 0)
                .ok()?;
        Some(info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec)
    }
}

// MARK: Linux

/// The fields of `/proc/<pid>/stat` after the name (which may hold spaces
/// and parentheses, so they are counted from its last parenthesis): state,
/// parent, group, session, terminal…
#[cfg(target_os = "linux")]
fn stat_fields(pid: u32) -> Option<Vec<String>> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = &stat[stat.rfind(')')? + 1..];
    Some(after.split_whitespace().map(str::to_owned).collect())
}

#[cfg(target_os = "linux")]
impl Processes for System {
    fn holders(&self, file: Identity) -> Vec<u32> {
        let own = std::process::id();
        let Ok(processes) = std::fs::read_dir("/proc") else {
            return Vec::new();
        };
        let mut found = Vec::new();
        for entry in processes.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            if pid == own {
                continue;
            }
            let Ok(descriptors) = std::fs::read_dir(entry.path().join("fd")) else {
                continue;
            };
            // Following the link gives the file itself, whatever its name
            // is now.
            let holds = descriptors.flatten().any(|descriptor| {
                std::fs::metadata(descriptor.path()).is_ok_and(|m| identity_of(&m) == file)
            });
            if holds {
                found.push(pid);
            }
        }
        found.sort_unstable();
        found
    }

    fn parent(&self, pid: u32) -> Option<u32> {
        stat_fields(pid)?.get(1)?.parse().ok()
    }

    fn exe(&self, pid: u32) -> Option<String> {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|path| path.display().to_string())
    }

    fn args(&self, pid: u32) -> Option<String> {
        let bytes = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
        let text: Vec<String> = bytes
            .split(|b| *b == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part).into_owned())
            .collect();
        (!text.is_empty()).then(|| text.join(" "))
    }

    fn tty(&self, pid: u32) -> Option<String> {
        let number: i64 = stat_fields(pid)?.get(4)?.parse().ok()?;
        (number != 0).then(|| number.to_string())
    }

    fn start_time(&self, pid: u32) -> Option<u64> {
        stat_fields(pid)?.get(19)?.parse().ok()
    }
}

// MARK: Elsewhere

/// Other systems: nothing is known.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
impl Processes for System {
    fn holders(&self, _: Identity) -> Vec<u32> {
        Vec::new()
    }

    fn parent(&self, _: u32) -> Option<u32> {
        None
    }

    fn exe(&self, _: u32) -> Option<String> {
        None
    }

    fn args(&self, pid: u32) -> Option<String> {
        checked_command_line(self, pid, command_line_by_ps)
    }

    fn tty(&self, _: u32) -> Option<String> {
        None
    }

    fn start_time(&self, _: u32) -> Option<u64> {
        None
    }
}

/// The identity of the file at `path`, followed through links.
pub fn identity_at(path: &Path) -> Option<Identity> {
    std::fs::metadata(path).ok().map(|m| identity_of(&m))
}

/// The identity of what is at `path` itself, a link not being followed.
#[cfg(test)]
pub fn identity_at_link(path: &Path) -> Option<Identity> {
    std::fs::symlink_metadata(path)
        .ok()
        .map(|m| identity_of(&m))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A process whose start time is read twice, and not the same twice: its
    /// identifier was given to another program while `ps` ran.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn a_command_line_is_only_taken_from_the_same_process() {
        use std::sync::Mutex;
        struct Starts(Mutex<Vec<Option<u64>>>);
        impl Processes for Starts {
            fn holders(&self, _: Identity) -> Vec<u32> {
                Vec::new()
            }
            fn parent(&self, _: u32) -> Option<u32> {
                None
            }
            fn exe(&self, _: u32) -> Option<String> {
                None
            }
            fn args(&self, _: u32) -> Option<String> {
                None
            }
            fn tty(&self, _: u32) -> Option<String> {
                None
            }
            fn start_time(&self, _: u32) -> Option<u64> {
                let mut answers = self.0.lock().unwrap();
                if answers.len() > 1 {
                    answers.remove(0)
                } else {
                    answers[0]
                }
            }
        }
        let ask = |_: u32| Some("node cli.js".to_owned());
        let same = Starts(Mutex::new(vec![Some(5), Some(5)]));
        assert_eq!(
            checked_command_line(&same, 9, ask).as_deref(),
            Some("node cli.js")
        );
        let reused = Starts(Mutex::new(vec![Some(5), Some(6)]));
        assert_eq!(checked_command_line(&reused, 9, ask), None);
        let gone = Starts(Mutex::new(vec![Some(5), None]));
        assert_eq!(checked_command_line(&gone, 9, ask), None);
        // `ps` finding nothing is nothing.
        assert_eq!(checked_command_line(&same, 9, |_| None), None);
        // A system that gives no start time at all is the same both times.
        let unknown = Starts(Mutex::new(vec![None, None]));
        assert_eq!(
            checked_command_line(&unknown, 9, ask).as_deref(),
            Some("node cli.js")
        );
    }

    /// The kernel's list of descriptors names the files this very process
    /// holds, by device and inode: it is how the readers of a FIFO are found,
    /// and the layout of the kernel's structure is only ours to get right.
    #[cfg(unix)]
    #[test]
    fn a_file_held_open_is_found_by_its_identity() {
        let dir = std::env::temp_dir().join(format!("vp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("held");
        let file = std::fs::File::create(&path).unwrap();
        let identity = identity_of(&file.metadata().unwrap());
        assert_eq!(identity_at(&path), Some(identity));
        // This process excludes itself from the holders, so look at what the
        // platform reports of ourselves directly.
        #[cfg(target_os = "macos")]
        {
            let me = i32::try_from(std::process::id()).unwrap();
            assert!(open_files(me).contains(&identity), "{identity:?}");
            // And a file that is closed is not there.
            drop(file);
            assert!(!open_files(me).contains(&identity));
        }
        #[cfg(not(target_os = "macos"))]
        drop(file);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A child that holds a file is a holder of it; one that does not, is not.
    #[test]
    fn a_child_that_holds_a_file_is_a_holder() {
        use std::process::{Command, Stdio};
        let dir = std::env::temp_dir().join(format!("vp2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("shared");
        std::fs::write(&path, "x").unwrap();
        let identity = identity_at(&path).unwrap();
        // `sleep` with the file as its standard input.
        let mut child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::from(std::fs::File::open(&path).unwrap()))
            .spawn()
            .unwrap();
        let pid = child.id();
        let found = (0..50).any(|_| {
            std::thread::sleep(std::time::Duration::from_millis(40));
            System.holders(identity).contains(&pid)
        });
        assert!(found, "the child was not found among the holders");
        // Whatever the file is called afterwards.
        let other = dir.join("renamed");
        std::fs::rename(&path, &other).unwrap();
        assert!(System.holders(identity).contains(&pid));
        assert!(System.exe(pid).is_some_and(|exe| exe.ends_with("sleep")));
        assert_eq!(System.parent(pid), Some(std::process::id()));
        assert!(System.start_time(pid).is_some());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!System.holders(identity).contains(&pid));
        std::fs::remove_dir_all(&dir).ok();
    }
}
