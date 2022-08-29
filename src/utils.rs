use super::system_calls::{RealSystemCalls, SystemCalls};
use nix::unistd::{self, Gid, Uid};
use std::os::unix::{ffi::OsStrExt, fs::PermissionsExt, process::CommandExt};
use std::{borrow::Cow, ffi::OsStr, fs, io, path::Path, path::PathBuf, process};
use thiserror::Error;

#[cfg(target_os = "linux")]
pub fn get_self_exe_path() -> io::Result<PathBuf> {
    std::fs::read_link("/proc/self/exe")
}

#[cfg(not(target_os = "linux"))]
pub fn get_self_exe_path() -> io::Result<PathBuf> {
    let args = std::env::args_os().collect::<Vec<std::ffi::OsString>>();
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
    const MAX_POSSIBLE_UID: u32 = 0xFFFF;
    return find_unused_uid_with_impl(min_uid, &mut RealSystemCalls {}, MAX_POSSIBLE_UID);
}

fn find_unused_uid_with_impl(
    min_uid: Uid,
    system_calls: &mut impl SystemCalls,
    max_possible_uid: u32,
) -> nix::Result<Option<Uid>> {
    let min_uid = min_uid.as_raw();

    for uid in (min_uid + 1)..=max_possible_uid {
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
    const MAX_POSSIBLE_GID: u32 = 0xFFFF;
    return find_unused_gid_with_impl(min_gid, &mut RealSystemCalls {}, MAX_POSSIBLE_GID);
}

fn find_unused_gid_with_impl(
    min_gid: Gid,
    system_calls: &mut impl SystemCalls,
    max_possible_gid: u32,
) -> nix::Result<Option<Gid>> {
    let min_gid = min_gid.as_raw();

    for gid in (min_gid + 1)..=max_possible_gid {
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
    modifier: impl FnMut(&mut Vec<Vec<u8>>),
) -> Vec<u8> {
    modify_etc_passwd_or_group_contents(passwd_content, 7, modifier)
}

/// Performs arbitrary modifications on a /etc/group-style file's contents.
///
/// Given the contents of a /etc/group-style file, this function parses each entry
/// as a collection of entry columns, and passes that collection to `modifier`
/// for arbitrary modification.
///
/// Returns the modified /etc/group content.
pub fn modify_etc_group_contents(
    group_file_content: &[u8],
    modifier: impl FnMut(&mut Vec<Vec<u8>>),
) -> Vec<u8> {
    modify_etc_passwd_or_group_contents(group_file_content, 4, modifier)
}

fn modify_etc_passwd_or_group_contents(
    content: &[u8],
    num_record_columns: usize,
    mut modifier: impl FnMut(&mut Vec<Vec<u8>>),
) -> Vec<u8> {
    let lines = content.split(|b| *b == b'\n').map(|line| {
        if line.is_empty() || line.starts_with(b"#") {
            return line.to_vec();
        }

        let mut columns: Vec<Vec<u8>> = line
            .split(|b| *b == b':')
            .map(|column| column.to_vec())
            .collect();
        if columns.len() < num_record_columns {
            return line.to_vec();
        }

        modifier(&mut columns);
        return columns.join(&b':');
    });

    let mut result = lines.collect::<Vec<Vec<u8>>>().join(&(b'\n'));
    if !result.ends_with(b"\n") {
        result.push(b'\n');
    }
    result
}

/// Contains details about a user account.
#[derive(Clone)]
pub struct UserDetails {
    pub name: String,
    pub uid: Uid,
    pub primary_gid: Gid,
    pub home: PathBuf,
    pub shell: PathBuf,
}

#[derive(Error, Debug)]
pub enum UserDetailsLookupError {
    #[error("Error looking up user database entry: {0}")]
    LookupError(#[source] nix::Error),

    #[error("User not found in user database")]
    NotFound,
}

/// Looks up a user account's details by its UID.
pub fn lookup_user_details_by_uid(uid: Uid) -> Result<UserDetails, UserDetailsLookupError> {
    let entry = match unistd::User::from_uid(uid) {
        Ok(Some(x)) => x,
        Ok(None) => return Err(UserDetailsLookupError::NotFound),
        Err(err) => return Err(UserDetailsLookupError::LookupError(err)),
    };
    Ok(UserDetails {
        name: entry.name,
        uid: uid,
        primary_gid: entry.gid,
        home: entry.dir,
        shell: entry.shell,
    })
}

/// Contains details about a group.
#[derive(Clone)]
pub struct GroupDetails {
    pub name: String,
    pub gid: Gid,
}

#[derive(Error, Debug)]
pub enum GroupDetailsLookupError {
    #[error("Error looking up group database entry: {0}")]
    LookupError(#[source] nix::Error),

    #[error("Group not found in group database")]
    NotFound,
}

/// Looks up a group's details by its GID.
pub fn lookup_group_details_by_gid(gid: Gid) -> Result<GroupDetails, GroupDetailsLookupError> {
    let entry = match unistd::Group::from_gid(gid) {
        Ok(Some(x)) => x,
        Ok(None) => return Err(GroupDetailsLookupError::NotFound),
        Err(err) => return Err(GroupDetailsLookupError::LookupError(err)),
    };
    Ok(GroupDetails {
        name: entry.name,
        gid: gid,
    })
}

#[derive(Error, Debug)]
pub enum ChownError {
    #[error("Path is invalid UTF-8")]
    PathInvalidUTF8,

    #[error("Process error: {0}")]
    CommandFailed(process::ExitStatus, String),

    #[error("I/O error: {0}")]
    IOError(#[source] io::Error, String),
}

/// Changes the ownership of a directory and its contents recursively, but without crossing.
/// filesystem boundaries.
///
/// Not crossing filesystem boundaries is important because the container may have mounts
/// under the home directory. For example, when using ekidd/rust-musl-builder the user is
/// supposed to mount a host directory into /home/rust/src.
///
/// We use 'find' instead of 'chown -R' in order not to cross filesystem
/// boundaries.
pub fn chown_dir_recursively_no_fs_boundary_crossing(
    path: &Path,
    uid: Uid,
    gid: Gid,
) -> Result<(), ChownError> {
    let path_str;

    match path.to_str() {
        Some(s) => path_str = s,
        None => return Err(ChownError::PathInvalidUTF8),
    }

    let command_string = format!(
        "find {} -xdev -print0 | xargs -0 -n 128 -x chown {}:{}",
        shell_escape::escape(Cow::from(path_str)),
        uid,
        gid
    );
    let result = process::Command::new("/bin/sh")
        .arg("-c")
        .arg(command_string.as_str())
        .status();
    match result {
        Ok(status) => {
            if status.success() {
                Ok(())
            } else {
                Err(ChownError::CommandFailed(status, command_string))
            }
        }
        Err(err) => Err(ChownError::IOError(err, command_string)),
    }
}

#[derive(Error, Debug)]
pub enum ListDirError {
    #[error("Error reading directory {0}: {1}")]
    ReadDirError(String, #[source] io::Error),

    #[error("Error reading directory entry from {0}: {1}")]
    ReadDirEntryError(String, #[source] io::Error),

    #[error("Error querying file metadata for {0}: {1}")]
    QueryMetaError(String, #[source] io::Error),
}

pub fn list_executable_files_sorted(dir: &impl AsRef<Path>) -> Result<Vec<PathBuf>, ListDirError> {
    let entries = fs::read_dir(&dir)
        .map_err(|err| ListDirError::ReadDirError(dir.as_ref().display().to_string(), err))?;
    let mut result = Vec::<PathBuf>::new();

    for entry in entries {
        let entry = entry.map_err(|err| {
            ListDirError::ReadDirEntryError(dir.as_ref().display().to_string(), err)
        })?;
        let metadata = entry
            .path()
            .metadata()
            .map_err(|err| ListDirError::QueryMetaError(entry.path().display().to_string(), err))?;

        if metadata.is_file() && (metadata.permissions().mode() & 0o111) != 0 {
            result.push(entry.path());
        }
    }

    result.sort_unstable();

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::super::system_calls::SystemCalls;
    use more_asserts::*;
    use nix::unistd::{Gid, Group, Uid, User};
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::{fs, fs::File, io, path::Path, thread, time::Duration};
    use tempfile::tempdir;

    fn create_file_return_ctime(path: &impl AsRef<Path>) -> io::Result<i64> {
        File::create(path)?;
        Ok(path.as_ref().metadata()?.ctime_nsec())
    }

    fn create_dir_return_ctime(path: &impl AsRef<Path>) -> io::Result<i64> {
        fs::create_dir(path)?;
        Ok(path.as_ref().metadata()?.ctime_nsec())
    }

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
                    Err(nix::Error::EOPNOTSUPP)
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
                    Err(nix::Error::EOPNOTSUPP)
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

        let new_contents = super::modify_etc_passwd_contents(orig_contents, |columns| {
            call_count += 1;

            assert_le!(call_count, 3);
            assert_eq!(7, columns.len());

            let string_columns: Vec<String> = columns
                .iter()
                .map(|item| String::from_utf8_lossy(&item).into_owned())
                .collect();

            if call_count == 1 {
                assert_eq!("root", &string_columns[0]);
                assert_eq!("*", &string_columns[1]);
                assert_eq!("0", &string_columns[2]);
                assert_eq!("0", &string_columns[3]);
                assert_eq!("System Administrator", &string_columns[4]);
                assert_eq!("/var/root", &string_columns[5]);
                assert_eq!("/bin/sh", &string_columns[6]);
            } else if call_count == 2 {
                assert_eq!("daemon", &string_columns[0]);
                assert_eq!("*", &string_columns[1]);
                assert_eq!("1", &string_columns[2]);
                assert_eq!("1", &string_columns[3]);
                assert_eq!("System Services", &string_columns[4]);
                assert_eq!("/var/root", &string_columns[5]);
                assert_eq!("/usr/bin/false", &string_columns[6]);
            } else {
                assert_eq!("nobody", &string_columns[0]);
                assert_eq!("*", &string_columns[1]);
                assert_eq!("-2", &string_columns[2]);
                assert_eq!("-2", &string_columns[3]);
                assert_eq!("Unprivileged User", &string_columns[4]);
                assert_eq!("/var/empty", &string_columns[5]);
                assert_eq!("/usr/bin/false", &string_columns[6]);
            }

            columns[0].push(b'2');
        });

        assert_eq!(3, call_count);
        assert_eq!(expected_contents, new_contents.as_slice());
    }

    #[test]
    fn modify_etc_group_contents() {
        let mut call_count = 0;
        let orig_contents = b"# This is a comment\n\
              # Another comment\n\
              \n\
              some invalid record\n\
              \n\
              nogroup:*:-1:\n\
              wheel:*:0:root\n\
              \n\
              daemon:*:1:root\n";
        let expected_contents = b"# This is a comment\n\
              # Another comment\n\
              \n\
              some invalid record\n\
              \n\
              nogroup2:*:-1:\n\
              wheel2:*:0:root\n\
              \n\
              daemon2:*:1:root\n";

        let new_contents = super::modify_etc_group_contents(orig_contents, |columns| {
            call_count += 1;

            assert_le!(call_count, 3);
            assert_eq!(4, columns.len());

            let string_columns: Vec<String> = columns
                .iter()
                .map(|item| String::from_utf8_lossy(&item).into_owned())
                .collect();

            if call_count == 1 {
                assert_eq!("nogroup", &string_columns[0]);
                assert_eq!("*", &string_columns[1]);
                assert_eq!("-1", &string_columns[2]);
                assert_eq!("", &string_columns[3]);
            } else if call_count == 2 {
                assert_eq!("wheel", &string_columns[0]);
                assert_eq!("*", &string_columns[1]);
                assert_eq!("0", &string_columns[2]);
                assert_eq!("root", &string_columns[3]);
            } else {
                assert_eq!("daemon", &string_columns[0]);
                assert_eq!("*", &string_columns[1]);
                assert_eq!("1", &string_columns[2]);
                assert_eq!("root", &string_columns[3]);
            }

            columns[0].push(b'2');
        });

        assert_eq!(3, call_count);
        assert_eq!(expected_contents, new_contents.as_slice());
    }

    #[test]
    fn lookup_user_details_by_uid() -> Result<(), super::UserDetailsLookupError> {
        let details = super::lookup_user_details_by_uid(Uid::current())?;
        assert_eq!(Uid::current(), details.uid);
        Ok(())
    }

    #[test]
    fn lookup_group_details_by_uid() -> Result<(), super::GroupDetailsLookupError> {
        let details = super::lookup_group_details_by_gid(Gid::current())?;
        assert_eq!(Gid::current(), details.gid);
        Ok(())
    }

    #[test]
    fn chown_dir_recursively_no_fs_boundary_crossing() -> io::Result<()> {
        let tempdir = tempdir()?;
        let file1_path = tempdir.path().join("file1");
        let subdir_path = tempdir.path().join("subdir");
        let file2_path = subdir_path.join("file2");

        let tempdir_orig_ctime = tempdir.path().metadata()?.ctime_nsec();
        let file1_orig_ctime = create_file_return_ctime(&file1_path)?;
        let subdir_orig_ctime = create_dir_return_ctime(&subdir_path)?;
        let file2_orig_ctime = create_dir_return_ctime(&file2_path)?;

        // Sleep some time to allow observing ctime changes.
        thread::sleep(Duration::from_millis(10));

        super::chown_dir_recursively_no_fs_boundary_crossing(
            tempdir.path(),
            Uid::current(),
            Gid::current(),
        )
        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

        assert_ne!(tempdir.path().metadata()?.ctime_nsec(), tempdir_orig_ctime);
        assert_ne!(file1_path.metadata()?.ctime_nsec(), file1_orig_ctime);
        assert_ne!(subdir_path.metadata()?.ctime_nsec(), subdir_orig_ctime);
        assert_ne!(file2_path.metadata()?.ctime_nsec(), file2_orig_ctime);

        Ok(())
    }

    fn create_file_with_mode(path: &impl AsRef<Path>, mode: u32) -> io::Result<()> {
        File::create(path)?;
        let mut permissions = path.as_ref().metadata()?.permissions();
        permissions.set_mode(mode);
        fs::set_permissions(path, permissions)?;
        Ok(())
    }

    fn create_dir_with_mode(path: &impl AsRef<Path>, mode: u32) -> io::Result<()> {
        fs::create_dir(path)?;
        let mut permissions = path.as_ref().metadata()?.permissions();
        permissions.set_mode(mode);
        fs::set_permissions(path, permissions)?;
        Ok(())
    }

    #[test]
    fn list_executable_files_sorted() -> io::Result<()> {
        let tempdir = tempdir()?;
        let exe1_path = tempdir.path().join("exe1");
        let exe2_path = tempdir.path().join("exe2");
        let exe3_path = tempdir.path().join("exe3");
        let exe4_path = tempdir.path().join("exe4");

        create_file_with_mode(&exe1_path, 0o755)?;
        create_file_with_mode(&exe2_path, 0o700)?;
        create_file_with_mode(&exe3_path, 0o070)?;
        create_file_with_mode(&exe4_path, 0o007)?;
        create_dir_with_mode(&tempdir.path().join("dir"), 0o755)?;
        create_file_with_mode(&tempdir.path().join("file1"), 0o600)?;

        let result = super::list_executable_files_sorted(&tempdir.path())
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

        assert_eq!(4, result.len());
        assert_eq!(exe1_path, result[0]);
        assert_eq!(exe2_path, result[1]);
        assert_eq!(exe3_path, result[2]);
        assert_eq!(exe4_path, result[3]);

        Ok(())
    }
}
