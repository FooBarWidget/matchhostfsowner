use super::system_calls::{RealSystemCalls, SystemCalls};
use nix::unistd::{self, Gid, Uid};
use std::os::unix::{ffi::OsStrExt, process::CommandExt};
use std::{env, ffi::OsStr, ffi::OsString, io, path::Path, path::PathBuf, process};
use thiserror::Error;

#[cfg(target_os = "linux")]
pub fn get_self_exe_path() -> io::Result<PathBuf> {
    fs::read_link("/proc/self/exe")
}

#[cfg(not(target_os = "linux"))]
pub fn get_self_exe_path() -> io::Result<PathBuf> {
    let args = env::args_os().collect::<Vec<OsString>>();
    Ok(PathBuf::from(&args[0]))
}

#[derive(Error, Debug)]
pub enum ReadLinkError {
    #[error("Process error: {0}")]
    CommandFailed(process::ExitStatus),

    #[error("I/O error: {0}")]
    IOError(#[source] io::Error),
}

/// For some reason, setuid root binaries cannot `readlink("/proc/1/exe")`
/// when the container is started with --user. Reading that symlink requires
/// the effective UID/GID to be the same as PID 1's UID/GID.
///
/// We work around this by shelling out to `readlink`. This subprocess drops
/// our effective UID/GID, leaving a normal UID/GID that's the same as PID 1's.
pub fn read_link_by_shelling_out(path: &Path) -> Result<PathBuf, ReadLinkError> {
    let mut command = process::Command::new("readlink");
    if cfg!(target_os = "linux") {
        command.arg("-v");
    }
    unsafe {
        command.pre_exec(drop_euid_egid_during_pre_exec);
    }

    let result = command
        .arg("-n")
        .arg(path)
        .stderr(process::Stdio::inherit())
        .output();

    match result {
        Ok(output) => {
            if output.status.success() {
                Ok(PathBuf::from(OsStr::from_bytes(&output.stdout)))
            } else {
                Err(ReadLinkError::CommandFailed(output.status))
            }
        }
        Err(io_err) => Err(ReadLinkError::IOError(io_err)),
    }
}

fn drop_euid_egid_during_pre_exec() -> io::Result<()> {
    unistd::setgid(unistd::getgid()).map_err(nix_to_io_error)?;
    unistd::setuid(unistd::getuid()).map_err(nix_to_io_error)?;
    Ok(())
}

fn nix_to_io_error(err: nix::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("{}", err))
}

/// Finds the first UID that's bigger than `min_uid` and for which no user account exists.
pub fn find_unused_uid(min_uid: Uid) -> nix::Result<Option<Uid>> {
    const MAX_POSSIBLE_UID: u64 = 0xFFFF;
    return find_unused_uid_with_impl(min_uid, &mut RealSystemCalls {}, MAX_POSSIBLE_UID);
}

fn find_unused_uid_with_impl(
    min_uid: Uid,
    system_calls: &mut impl SystemCalls,
    max_possible_uid: u64,
) -> nix::Result<Option<Uid>> {
    let min_uid = min_uid.as_raw();

    for uid in (min_uid + 1)..((max_possible_uid + 1) as u32) {
        match system_calls.lookup_user_by_uid(Uid::from_raw(uid)) {
            Ok(Some(_)) => continue,
            Ok(None) => return Ok(Some(Uid::from_raw(uid))),
            Err(err) => return Err(err),
        }
    }

    Ok(None)
}

/// Finds the first GID that's bigger than `min_gid` and for which no group account exists.
pub fn find_unused_gid(min_gid: Gid) -> nix::Result<Option<Gid>> {
    const MAX_POSSIBLE_GID: u64 = 0xFFFF;
    return find_unused_gid_with_impl(min_gid, &mut RealSystemCalls {}, MAX_POSSIBLE_GID);
}

fn find_unused_gid_with_impl(
    min_gid: Gid,
    system_calls: &mut impl SystemCalls,
    max_possible_gid: u64,
) -> nix::Result<Option<Gid>> {
    let min_gid = min_gid.as_raw();

    for gid in (min_gid + 1)..((max_possible_gid + 1) as u32) {
        match system_calls.lookup_group_by_gid(Gid::from_raw(gid)) {
            Ok(Some(_)) => continue,
            Ok(None) => return Ok(Some(Gid::from_raw(gid))),
            Err(err) => return Err(err),
        };
    }

    Ok(None)
}

/// Performs arbitrary modifications on a /etc/passwd-style file's contents.
///
/// Given the contents of a passwd-style file, this function parses each entry
/// as a collection of entry columns, and passes that collection to `modifier`
/// for arbitrary modification.
///
/// Returns the modified passwd content.
pub fn modify_etc_passwd_contents(
    passwd_content: &[u8],
    mut modifier: impl FnMut(&mut Vec<Vec<u8>>),
) -> Vec<u8> {
    let lines = passwd_content.split(|b| *b == b'\n').map(|line| {
        if line.is_empty() || line.starts_with(b"#") {
            return line.to_vec();
        }

        let mut items: Vec<Vec<u8>> = line
            .split(|b| *b == b':')
            .map(|item| item.to_vec())
            .collect();
        if items.len() < 7 {
            return line.to_vec();
        }

        modifier(&mut items);
        return items.join(&b':');
    });

    let mut result = lines.collect::<Vec<Vec<u8>>>().join(&(b'\n'));
    if !result.ends_with(b"\n") {
        result.push(b'\n');
    }
    result
}

#[cfg(test)]
mod tests {
    use super::super::system_calls::SystemCalls;
    use more_asserts::*;
    use nix::unistd::{Gid, Group, Uid, User};
    use std::os::unix::fs::symlink;
    use std::{fs::File, io};
    use tempfile::tempdir;

    #[test]
    fn get_self_exe_path() -> io::Result<()> {
        super::get_self_exe_path()?;
        Ok(())
    }

    #[test]
    fn read_link_by_shelling_out() -> io::Result<()> {
        let tempdir = tempdir()?;

        let file_path = tempdir.path().join("file1");
        let link_path = tempdir.path().join("link1");
        File::create(file_path.as_path())?;
        symlink(file_path.as_path(), link_path.as_path())?;
        match super::read_link_by_shelling_out(link_path.as_path()) {
            Ok(path) => assert_eq!(file_path.as_path(), path.as_path()),
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
        };

        let link_path = tempdir.path().join("link2");
        match super::read_link_by_shelling_out(link_path.as_path()) {
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "link is supposed to be broken",
                ))
            }
            Err(super::ReadLinkError::CommandFailed(status)) => {
                assert!(!status.success(), "reading link fails")
            }
            Err(super::ReadLinkError::IOError(e)) => return Err(e),
        };

        Ok(())
    }

    #[test]
    fn find_unused_uid_has_match() -> nix::Result<()> {
        struct MockSystemCalls {
            call_count: u32,
        }

        impl SystemCalls for MockSystemCalls {
            fn lookup_user_by_uid(self: &mut Self, uid: Uid) -> nix::Result<Option<User>> {
                self.call_count += 1;
                if uid.as_raw() <= 5 {
                    Ok(Some(User::from_uid(Uid::current()).unwrap().unwrap()))
                } else {
                    Ok(None)
                }
            }
        }

        let mut system_calls = MockSystemCalls { call_count: 0 };
        let result = super::find_unused_uid_with_impl(Uid::from_raw(0), &mut system_calls, 10)?;
        assert!(result.is_some(), "A UID is found");
        assert_eq!(6, system_calls.call_count);

        Ok(())
    }

    #[test]
    fn find_unused_uid_no_match() -> nix::Result<()> {
        struct MockSystemCalls {
            call_count: u32,
            max_uid: u32,
        }

        impl SystemCalls for MockSystemCalls {
            fn lookup_user_by_uid(self: &mut Self, uid: Uid) -> nix::Result<Option<User>> {
                assert_le!(uid.as_raw(), 5);
                self.call_count += 1;
                self.max_uid = self.max_uid.max(uid.as_raw());
                Ok(Some(User::from_uid(Uid::current()).unwrap().unwrap()))
            }
        }

        let mut system_calls = MockSystemCalls {
            call_count: 0,
            max_uid: 0,
        };
        let result = super::find_unused_uid_with_impl(Uid::from_raw(0), &mut system_calls, 3)?;
        assert!(result.is_none(), "No UID found");
        assert_eq!(3, system_calls.call_count);
        assert_eq!(3, system_calls.max_uid);

        Ok(())
    }

    #[test]
    fn find_unused_uid_error() -> nix::Result<()> {
        struct MockSystemCalls {
            call_count: u32,
        }

        impl SystemCalls for MockSystemCalls {
            fn lookup_user_by_uid(self: &mut Self, uid: Uid) -> nix::Result<Option<User>> {
                self.call_count += 1;
                if uid.as_raw() <= 5 {
                    Ok(Some(User::from_uid(Uid::current()).unwrap().unwrap()))
                } else {
                    Err(nix::Error::UnsupportedOperation)
                }
            }
        }

        let mut system_calls = MockSystemCalls { call_count: 0 };
        let result = super::find_unused_uid_with_impl(Uid::from_raw(0), &mut system_calls, 10);
        assert!(result.is_err());
        assert_eq!(6, system_calls.call_count);

        Ok(())
    }

    #[test]
    fn find_unused_gid_has_match() -> nix::Result<()> {
        struct MockSystemCalls {
            call_count: u32,
        }

        impl SystemCalls for MockSystemCalls {
            fn lookup_group_by_gid(self: &mut Self, gid: Gid) -> nix::Result<Option<Group>> {
                self.call_count += 1;
                if gid.as_raw() <= 5 {
                    Ok(Some(Group::from_gid(Gid::current()).unwrap().unwrap()))
                } else {
                    Ok(None)
                }
            }
        }

        let mut system_calls = MockSystemCalls { call_count: 0 };
        let result = super::find_unused_gid_with_impl(Gid::from_raw(0), &mut system_calls, 10)?;
        assert!(result.is_some(), "A GID is found");
        assert_eq!(6, system_calls.call_count);

        Ok(())
    }

    #[test]
    fn find_unused_gid_no_match() -> nix::Result<()> {
        struct MockSystemCalls {
            call_count: u32,
            max_gid: u32,
        }

        impl SystemCalls for MockSystemCalls {
            fn lookup_group_by_gid(self: &mut Self, gid: Gid) -> nix::Result<Option<Group>> {
                assert_le!(gid.as_raw(), 5);
                self.call_count += 1;
                self.max_gid = self.max_gid.max(gid.as_raw());
                Ok(Some(Group::from_gid(Gid::current()).unwrap().unwrap()))
            }
        }

        let mut system_calls = MockSystemCalls {
            call_count: 0,
            max_gid: 0,
        };
        let result = super::find_unused_gid_with_impl(Gid::from_raw(0), &mut system_calls, 3)?;
        assert!(result.is_none(), "No GID found");
        assert_eq!(3, system_calls.call_count);
        assert_eq!(3, system_calls.max_gid);

        Ok(())
    }

    #[test]
    fn find_unused_gid_error() -> nix::Result<()> {
        struct MockSystemCalls {
            call_count: u32,
        }

        impl SystemCalls for MockSystemCalls {
            fn lookup_group_by_gid(self: &mut Self, gid: Gid) -> nix::Result<Option<Group>> {
                self.call_count += 1;
                if gid.as_raw() <= 5 {
                    Ok(Some(Group::from_gid(Gid::current()).unwrap().unwrap()))
                } else {
                    Err(nix::Error::UnsupportedOperation)
                }
            }
        }

        let mut system_calls = MockSystemCalls { call_count: 0 };
        let result = super::find_unused_gid_with_impl(Gid::from_raw(0), &mut system_calls, 10);
        assert!(result.is_err());
        assert_eq!(6, system_calls.call_count);

        Ok(())
    }

    #[test]
    fn modify_etc_passwd_contents() {
        let mut call_count = 0;
        let orig_contents = b"# This is a comment\n\
              # Another comment\n\
              \n\
              some invalid record\n\
              \n\
              root:*:0:0:System Administrator:/var/root:/bin/sh\n\
              daemon:*:1:1:System Services:/var/root:/usr/bin/false\n\
              \n\
              nobody:*:-2:-2:Unprivileged User:/var/empty:/usr/bin/false\n";
        let expected_contents = b"# This is a comment\n\
              # Another comment\n\
              \n\
              some invalid record\n\
              \n\
              root2:*:0:0:System Administrator:/var/root:/bin/sh\n\
              daemon2:*:1:1:System Services:/var/root:/usr/bin/false\n\
              \n\
              nobody2:*:-2:-2:Unprivileged User:/var/empty:/usr/bin/false\n";

        let new_contents = super::modify_etc_passwd_contents(orig_contents, |entry| {
            call_count += 1;

            assert_le!(call_count, 3);
            assert_eq!(7, entry.len());

            let string_entry: Vec<String> = entry
                .iter()
                .map(|item| String::from_utf8_lossy(&item).into_owned())
                .collect();

            if call_count == 1 {
                assert_eq!("root", &string_entry[0]);
                assert_eq!("*", &string_entry[1]);
                assert_eq!("0", &string_entry[2]);
                assert_eq!("0", &string_entry[3]);
                assert_eq!("System Administrator", &string_entry[4]);
                assert_eq!("/var/root", &string_entry[5]);
                assert_eq!("/bin/sh", &string_entry[6]);
            } else if call_count == 2 {
                assert_eq!("daemon", &string_entry[0]);
                assert_eq!("*", &string_entry[1]);
                assert_eq!("1", &string_entry[2]);
                assert_eq!("1", &string_entry[3]);
                assert_eq!("System Services", &string_entry[4]);
                assert_eq!("/var/root", &string_entry[5]);
                assert_eq!("/usr/bin/false", &string_entry[6]);
            } else {
                assert_eq!("nobody", &string_entry[0]);
                assert_eq!("*", &string_entry[1]);
                assert_eq!("-2", &string_entry[2]);
                assert_eq!("-2", &string_entry[3]);
                assert_eq!("Unprivileged User", &string_entry[4]);
                assert_eq!("/var/empty", &string_entry[5]);
                assert_eq!("/usr/bin/false", &string_entry[6]);
            }

            entry[0].push(b'2');
        });

        assert_eq!(3, call_count);
        assert_eq!(expected_contents, new_contents.as_slice());
    }
}
