mod abort;
mod config;
mod os_group;
mod simple_logger;

use config::{load_config, Config};
use failure::Fail;
use libc;
use log::{debug, error, info, trace, warn, Level};
use nix::unistd::{self, Gid, Uid};
use os_group::OsGroup;
use pwd::{self, Passwd, PwdError};
use shell_escape;
use std::ffi::{CString, OsString};
use std::os::unix::{ffi::OsStringExt, fs::MetadataExt, fs::PermissionsExt};
use std::result::Result;
use std::{borrow::Cow, env, fs, io, path::PathBuf, process};

fn initialize_logger() {
    simple_logger::init_with_level(Level::Info).unwrap_or_else(|err| {
        eprintln!("*** ERROR initializing logger: {}", err);
        process::exit(1);
    });
}

// Since this program is supposed to be run with the setuid root biit,
// we must only allow it to be run in very specific circumstances
// that are deemed safe.
fn check_running_allowed() {
    if unistd::geteuid().is_root() {
        // If we have root privileges, then it is safe if:
        // - We are running as PID 1.
        // - The root privilege was not obtained via the setuid root bit.
        if unistd::getpid().as_raw() != 1 && !unistd::getuid().is_root() {
            abort!(
                "This program may only be run when one \
                 of the following conditions apply:\n\
                 \n \
                 - This program is run as PID 1.\n \
                 - This program is run with root privileges (but not \
                 via the setuid root bit)."
            );
        }
    } else if !allow_non_root() {
        // We don't have the setuid root bit set.

        let self_exe_path = get_self_exe_path();
        let self_exe_desc: String;
        let self_exe_path_str: String;
        match self_exe_path {
            Ok(path) => {
                self_exe_desc = path.to_string_lossy().into_owned();
                self_exe_path_str = self_exe_desc.clone();
            }
            Err(err) => {
                warn!("Error reading symlink /proc/self/exe: {}", err);
                self_exe_desc = String::from("this program's executable file");
                self_exe_path_str = String::from("/path-to-this-program's-exe");
            }
        };

        abort!(
            "This program requires root privileges to operate.\n\
             \n \
             - First time running this program in this container?\n   \
             Then this probably means that you didn't set the setuid root bit \
             on {}. Please set it with:\n\
             \n     \
             chown root: {}\n     \
             chmod +s {}\n\
             \n \
             - Not the first time?\n   \
             Then this error is normal. For security reasons, this program \
             may only be invoked once, so this program drops its own setuid \
             root bit after executing once.\n\
             \n \
             - Hint: set ACU_ALLOW_NON_ROOT=1 to force running this \
             program despite not having root privileges.",
            self_exe_desc,
            self_exe_path_str,
            self_exe_path_str
        );
    }
}

#[cfg(any(target_os = "linux"))]
fn get_self_exe_path() -> io::Result<PathBuf> {
    fs::read_link("/proc/self/exe")
}

#[cfg(not(any(target_os = "linux")))]
fn get_self_exe_path() -> io::Result<PathBuf> {
    let args = env::args_os().collect::<Vec<OsString>>();
    Ok(PathBuf::from(&args[0]))
}

fn allow_non_root() -> bool {
    match env::var("ACU_ALLOW_NON_ROOT") {
        Ok(val) => config::parse_bool_str(&val).unwrap_or(false),
        Err(env::VarError::NotPresent) => false,
        Err(env::VarError::NotUnicode(_)) => false,
    }
}

fn reconfigure_logger(config: &Config) {
    log::set_max_level(config.log_level.to_level_filter());
    debug!("Configuration: {:#?}", config);
}

fn debug_print_process_privileges() {
    debug!(
        "Current process's privileges: uid={} gid={} euid={} egid={}",
        unistd::getuid(),
        unistd::getgid(),
        unistd::geteuid(),
        unistd::getegid()
    );
}

fn drop_setuid_root_bit_on_self_exe_if_necessary() {
    let path = get_self_exe_path().unwrap_or_else(|err| {
        abort!(
            "Error dropping setuid bit on this program's own executable: \
             error reading symlink /proc/self/exe: {}",
            err
        );
    });
    let meta = fs::metadata(&path).unwrap_or_else(|err| {
        abort!(
            "Error dropping setuid bit on this program's own executable: \
             error stat()'ing /proc/self/exe: {}",
            err
        );
    });
    let perms = meta.permissions();
    if (perms.mode() & 0o4000) == 0 {
        debug!("No setuid bit detected on {}.", path.display().to_string());
    } else {
        debug!("Dropping setuid bit on {}.", path.display().to_string());
        let mut perms = perms;
        perms.set_mode(perms.mode() & !0o6000);
        fs::set_permissions(path, perms).unwrap_or_else(|err| {
            abort!(
                "Error dropping setuid bit on this program's own executable: {}",
                err
            );
        });
    }
}

#[derive(Debug, Fail)]
#[fail(display = "Error stat()'ing /proc/1: {}", _0)]
struct Proc1StatError(#[cause] io::Error);

fn lookup_target_account_uid_gid(config: &Config) -> Result<(Uid, Gid), Proc1StatError> {
    if config.target_uid.is_some() && config.target_gid.is_some() {
        debug!("Using target UID/GID specified by configuration.");
        return Ok((config.target_uid.unwrap(), config.target_gid.unwrap()));
    }

    if config.target_uid.is_some() {
        debug!("Using target UID specified by configuration.");
    } else if config.target_gid.is_some() {
        debug!("Using target GID specified by configuration.");
    }

    if unistd::getpid().as_raw() == 1 {
        Ok((
            config.target_uid.unwrap_or(unistd::getuid()),
            config.target_gid.unwrap_or(unistd::getgid()),
        ))
    } else {
        debug!("Looking up target UID/GID by querying /proc/1.");
        lookup_target_uid_gid_from_proc(config)
    }
}

fn lookup_target_uid_gid_from_proc(config: &Config) -> Result<(Uid, Gid), Proc1StatError> {
    let meta = fs::metadata("/proc/1").map_err(|err| Proc1StatError(err))?;
    Ok((
        config.target_uid.unwrap_or(Uid::from_raw(meta.uid())),
        config.target_gid.unwrap_or(Gid::from_raw(meta.gid())),
    ))
}

fn lookup_target_account_uid_gid_or_abort(config: &Config) -> (Uid, Gid) {
    let (uid, gid) = lookup_target_account_uid_gid(&config).unwrap_or_else(|err| {
        abort!("Error looking up target UID/GID: {}", err);
    });
    debug!("Target account UID/GID = {}:{}", uid, gid);
    (uid, gid)
}

#[derive(Clone)]
struct AccountDetails {
    uid: Uid,
    gid: Gid,
    name: String,
    home: String,
    shell: String,
    group_name: String,
}

#[derive(Debug, Fail)]
enum AccountDetailsLookupError {
    #[fail(display = "Error looking up user database entry: {}", _0)]
    UserLookupError(#[cause] PwdError),

    #[fail(display = "User not found in user database")]
    UserNotFound,

    #[fail(display = "Error looking up group database entry: {}", _0)]
    GroupLookupError(#[cause] os_group::Error),

    #[fail(
        display = "User's primary group (GID {}) not found in group database",
        _0
    )]
    PrimaryGroupNotFound(Gid),
}

fn lookup_app_account_details(
    config: &Config,
) -> Result<AccountDetails, AccountDetailsLookupError> {
    let entry = match Passwd::from_name(config.app_account.as_str()) {
        Ok(Some(x)) => x,
        Ok(None) => return Err(AccountDetailsLookupError::UserNotFound),
        Err(err) => return Err(AccountDetailsLookupError::UserLookupError(err)),
    };

    let gid = config
        .mock_app_account_gid
        .unwrap_or(Gid::from_raw(entry.gid));
    let grp_entry = match OsGroup::from_gid(gid) {
        Ok(Some(x)) => x,
        Ok(None) => return Err(AccountDetailsLookupError::PrimaryGroupNotFound(gid)),
        Err(err) => return Err(AccountDetailsLookupError::GroupLookupError(err)),
    };

    Ok(AccountDetails {
        uid: config
            .mock_app_account_uid
            .unwrap_or(Uid::from_raw(entry.uid)),
        gid: gid,
        name: entry.name,
        home: entry.dir,
        shell: entry.shell,
        group_name: grp_entry.name,
    })
}

fn lookup_app_account_details_or_abort(config: &Config) -> AccountDetails {
    let acc_details = lookup_app_account_details(&config).unwrap_or_else(|err| {
        abort!(
            "Error looking up details for OS user account '{}': {}",
            config.app_account,
            err
        );
    });
    debug!(
        "App account's ('{}') UID:GID = {}:{}",
        config.app_account, acc_details.uid, acc_details.gid,
    );
    acc_details
}

fn sanity_check_app_account_details(config: &Config, app_account_details: &AccountDetails) {
    if app_account_details.uid.is_root() {
        abort!(
            "The configured app account ({}) has UID 0 (root). \
             This is not allowed, please configure a different \
             app account.",
            config.app_account
        );
    }
    if app_account_details.gid.as_raw() == 0 {
        abort!(
            "The configured app account ({}) belongs to a primary \
             group whose GID is 0 ('{}', the root group). This is not \
             allowed, please configure a different app account.",
            config.app_account,
            app_account_details.group_name
        );
    }
}

// If we got root privileges via the setuid root bit, then
// we must `setgid(geteuid())` and `setuid(geteuid())` so that
// child processes (e.g. hooks) also get root privileges.
fn embrace_setuid_bit_privileges_if_provided() {
    if unistd::getuid() == unistd::geteuid() || !unistd::geteuid().is_root() {
        debug!("No setuid root bit privileges detected.");
        return;
    }

    debug!(
        "Synchronizing process GID with effective GID ({}).",
        unistd::getegid()
    );
    unistd::setgid(unistd::getegid()).unwrap_or_else(|err| {
        abort!(
            "Error changing process GID to {}: {}",
            unistd::getegid(),
            err
        );
    });

    debug!(
        "Synchronizing process UID with effective UID ({}).",
        unistd::geteuid()
    );
    unistd::setuid(unistd::geteuid()).unwrap_or_else(|err| {
        abort!(
            "Error changing process UID to {}: {}",
            unistd::geteuid(),
            err
        );
    });
}

fn lookup_account_with_uid(uid: Uid) -> Result<Option<Passwd>, pwd::PwdError> {
    match Passwd::from_uid(uid.as_raw()) {
        Some(i) => Ok(Some(i)),
        None => Ok(None),
    }
}

fn find_unused_uid(min_uid: Uid) -> Option<Uid> {
    const MAX_POSSIBLE_UID: u64 = 0xFFFF;
    let min_uid = min_uid.as_raw();
    let max_uid = (min_uid as u64 + MAX_POSSIBLE_UID).min(MAX_POSSIBLE_UID) as u32;

    for uid in min_uid + 1..max_uid {
        if Passwd::from_uid(uid).is_none() {
            return Some(Uid::from_raw(uid));
        }
    }

    None
}

fn find_unused_gid(min_gid: Gid) -> Result<Option<Gid>, os_group::Error> {
    const MAX_POSSIBLE_GID: u64 = 0xFFFF;
    let min_gid = min_gid.as_raw();
    let max_gid = (min_gid as u64 + MAX_POSSIBLE_GID).min(MAX_POSSIBLE_GID) as u32;

    for gid in min_gid + 1..max_gid {
        match OsGroup::from_gid(Gid::from_raw(gid)) {
            Ok(Some(_)) => continue,
            Ok(None) => return Ok(Some(Gid::from_raw(gid))),
            Err(err) => return Err(err),
        };
    }

    Ok(None)
}

#[derive(Debug, Fail)]
enum AccountModifyError {
    #[fail(display = "Error reading /etc/passwd: {}", _0)]
    PasswdReadError(#[cause] io::Error),

    #[fail(display = "Error writing /etc/passwd: {}", _0)]
    PasswdWriteError(#[cause] io::Error),

    #[fail(display = "Error reading /etc/group: {}", _0)]
    GroupReadError(#[cause] io::Error),

    #[fail(display = "Error writing /etc/group: {}", _0)]
    GroupWriteError(#[cause] io::Error),
}

type BinaryString = Vec<u8>;

fn modify_etc_passwd(
    dry_run: bool,
    modifier: impl Fn(&mut Vec<BinaryString>),
) -> Result<(), AccountModifyError> {
    let content =
        fs::read("/etc/passwd").map_err(|err| AccountModifyError::PasswdReadError(err))?;

    let lines = content.split(|b| *b == b'\n').map(|line| {
        if line.is_empty() || line.starts_with(b"#") {
            return line.to_vec();
        }

        let mut items: Vec<BinaryString> = line
            .split(|b| *b == b':')
            .map(|item| item.to_vec())
            .collect();
        if items.len() < 7 {
            return line.to_vec();
        }

        modifier(&mut items);
        return items.join(&b':');
    });

    let mut result = lines.collect::<Vec<BinaryString>>().join(&(b'\n'));
    if !result.ends_with(b"\n") {
        result.push(b'\n');
    }

    if dry_run {
        info!("Dry-run mode on, so not actually modifying /etc/passwd.");
        trace!(
            "But would otherwise have modified it to:\n\
             ---- BEGIN PASSWD ----\n\
             {}\
             ---- END PASSWD ----",
            String::from_utf8_lossy(&result)
        );
    } else {
        trace!(
            "Modifying /etc/passwd to:\n\
             ---- BEGIN PASSWD ----\n\
             {}\
             ---- END PASSWD ----",
            String::from_utf8_lossy(&result)
        );
        fs::write("/etc/passwd", result)
            .map_err(|err| AccountModifyError::PasswdWriteError(err))?;
    }

    // Ensure that future getpwuid() calls correctly look up our updated information.
    unsafe {
        libc::endpwent();
    }

    Ok(())
}

fn modify_account_uid_gid<'a>(
    config: &Config,
    old_uid: Uid,
    new_uid: Uid,
    new_gid: Gid,
) -> Result<(), AccountModifyError> {
    let old_uid_string = old_uid.to_string();
    modify_etc_passwd(config.dry_run, |items: &mut Vec<BinaryString>| {
        if items[2] == old_uid_string.as_bytes() {
            items[2] = new_uid.as_raw().to_string().as_bytes().to_vec();
            items[3] = new_gid.as_raw().to_string().as_bytes().to_vec();
        }
    })
}

fn modify_group_gid(config: &Config, old_gid: Gid, new_gid: Gid) -> Result<(), AccountModifyError> {
    let old_gid_string = old_gid.to_string();
    let content = fs::read("/etc/group").map_err(|err| AccountModifyError::GroupReadError(err))?;

    let lines = content.split(|b| *b == b'\n').map(|line| {
        if line.is_empty() || line.starts_with(b"#") {
            return line.to_vec();
        }

        let mut items: Vec<BinaryString> = line
            .split(|b| *b == b':')
            .map(|item| item.to_vec())
            .collect();
        if items.len() < 4 {
            return line.to_vec();
        }

        if items[2] == old_gid_string.as_bytes() {
            items[2] = new_gid.as_raw().to_string().as_bytes().to_vec();
        }

        return items.join(&b':');
    });

    let mut result = lines.collect::<Vec<BinaryString>>().join(&(b'\n'));
    if !result.ends_with(b"\n") {
        result.push(b'\n');
    }

    if config.dry_run {
        info!("Dry-run mode on, so not actually modifying /etc/group.");
        trace!(
            "But would otherwise have modified it to:\n\
             ---- BEGIN GROUP ----\n\
             {}\
             ---- END GROUP ----",
            String::from_utf8_lossy(&result)
        );
    } else {
        trace!(
            "Modifying /etc/group to:\n\
             ---- BEGIN GROUP ----\n\
             {}\
             ---- END GROUP ----",
            String::from_utf8_lossy(&result)
        );
        fs::write("/etc/group", result).map_err(|err| AccountModifyError::GroupWriteError(err))?;
    }

    // Ensure that future getgrgid() calls correctly look up our updated information.
    unsafe {
        libc::endgrent();
    }

    modify_etc_passwd(config.dry_run, |items: &mut Vec<BinaryString>| {
        if items[3] == old_gid_string.as_bytes() {
            items[3] = new_gid.as_raw().to_string().as_bytes().to_vec();
        }
    })
}

fn ensure_no_account_already_using_target_uid(config: &Config, target_uid: Uid) {
    debug!(
        "Checking whether the target UID ({}) is already occupied by an existing account.",
        target_uid
    );
    match lookup_account_with_uid(target_uid) {
        Ok(Some(conflicting_account)) => {
            debug!(
                "Target UID ({}) already occupied by account '{}'. \
                 Will change that account's UID.",
                target_uid, conflicting_account.name
            );
            let new_uid = find_unused_uid(target_uid).unwrap_or_else(|| {
                abort!(
                    "Error changing conflicting account '{}': \
                     cannot find an unused UID that's larger than {}",
                    conflicting_account.name,
                    target_uid
                );
            });

            debug!(
                "Changing conflicting account '{}' UID: {} -> {}",
                conflicting_account.name, target_uid, new_uid
            );
            modify_account_uid_gid(
                &config,
                target_uid,
                new_uid,
                Gid::from_raw(conflicting_account.gid),
            )
            .unwrap_or_else(|err| {
                abort!(
                    "Error changing conflicting account '{}' UID from {} to {}: {}",
                    conflicting_account.name,
                    target_uid,
                    new_uid,
                    err
                );
            });
        }
        Ok(None) => debug!(
            "Target UID ({}) not already occupied by existing account.",
            target_uid
        ),
        Err(err) => {
            abort!(
                "Error checking whether the target UID ({}) \
                 is already occupied by an existing account: {}",
                target_uid,
                err
            );
        }
    };
}

fn ensure_app_account_has_target_uid_and_gid(
    config: &Config,
    app_account_details: &AccountDetails,
    target_uid: Uid,
    target_gid: Gid,
) {
    debug!(
        "Changing account '{}' UID/GID ({}:{}) to match target UID/GID ({}:{}).",
        config.app_account,
        app_account_details.uid,
        app_account_details.gid,
        target_uid,
        target_gid
    );
    modify_account_uid_gid(config, app_account_details.uid, target_uid, target_gid).unwrap_or_else(
        |err| {
            abort!(
                "Error changing account '{}' UID/GID from {}:{} to {}:{}: {}",
                config.app_account,
                app_account_details.uid,
                app_account_details.gid,
                target_uid,
                target_gid,
                err
            );
        },
    );
}

fn ensure_no_group_already_using_target_gid(config: &Config, target_gid: Gid) {
    debug!(
        "Checking whether the target GID ({}) is already occupied by an existing group.",
        target_gid
    );
    match OsGroup::from_gid(target_gid) {
        Ok(Some(conflicting_group)) => {
            debug!(
                "Target GID ({}) already occupied by group '{}'. \
                 Will change that group's GID.",
                target_gid, conflicting_group.name
            );
            let new_gid = find_unused_gid(target_gid).unwrap_or_else(|err| {
                abort!(
                    "Error changing conflicting group '{}': \
                     error finding an unused GID that's larger \
                     than {}: {}",
                    conflicting_group.name,
                    target_gid,
                    err
                );
            });
            let new_gid = new_gid.unwrap_or_else(|| {
                abort!(
                    "Error changing conflicting group '{}': \
                     cannot find an unused GID that's larger than {}",
                    conflicting_group.name,
                    target_gid
                );
            });

            debug!(
                "Changing conflicting group '{}' GID: {} -> {}",
                conflicting_group.name, target_gid, new_gid
            );
            modify_group_gid(&config, target_gid, new_gid).unwrap_or_else(|err| {
                abort!(
                    "Error changing conflicting group '{}' GID from {} to {}: {}",
                    conflicting_group.name,
                    target_gid,
                    new_gid,
                    err
                );
            });
        }
        Ok(None) => debug!(
            "Target GID ({}) not already occupied by existing group.",
            target_gid
        ),
        Err(err) => {
            abort!(
                "Error checking whether the target GID ({}) \
                 is already occupied by an existing group: {}",
                target_gid,
                err
            );
        }
    };
}

fn ensure_app_group_has_target_gid(
    config: &Config,
    app_account_details: &AccountDetails,
    target_gid: Gid,
) {
    debug!(
        "Changing group '{}' GID ({}) to match the target GID ({}).",
        app_account_details.group_name, app_account_details.gid, target_gid
    );
    modify_group_gid(&config, app_account_details.gid, target_gid).unwrap_or_else(|err| {
        abort!(
            "Error changing group '{}' GID from {} to {}: {}",
            app_account_details.group_name,
            app_account_details.gid,
            target_gid,
            err
        );
    });
}

fn lookup_target_account_details(
    target_uid: Uid,
    target_gid: Gid,
) -> Result<AccountDetails, AccountDetailsLookupError> {
    let entry = match lookup_account_with_uid(target_uid) {
        Ok(Some(x)) => x,
        Ok(None) => return Err(AccountDetailsLookupError::UserNotFound),
        Err(err) => return Err(AccountDetailsLookupError::UserLookupError(err)),
    };

    let grp_entry = match OsGroup::from_gid(target_gid) {
        Ok(Some(x)) => x,
        Ok(None) => return Err(AccountDetailsLookupError::PrimaryGroupNotFound(target_gid)),
        Err(err) => return Err(AccountDetailsLookupError::GroupLookupError(err)),
    };

    Ok(AccountDetails {
        uid: target_uid,
        gid: target_gid,
        name: entry.name,
        home: entry.dir,
        shell: entry.shell,
        group_name: grp_entry.name,
    })
}

fn lookup_target_account_details_or_abort(
    config: &Config,
    target_uid: Uid,
    target_gid: Gid,
    using_app_account: bool,
) -> AccountDetails {
    let details = lookup_target_account_details(target_uid, target_gid).unwrap_or_else(|err| {
        if using_app_account {
            abort!(
                "Error looking up app account ('{}') details (UID/GID {}:{}): {}",
                config.app_account,
                target_uid,
                target_gid,
                err
            );
        } else {
            abort!(
                "Error looking up OS account details for UID/GID {}:{}: {}",
                target_uid,
                target_gid,
                err
            );
        }
    });
    debug!(
        "Target account is '{}' (UID/GID = {}:{}, group = {}, home = {}).",
        details.name, target_uid, target_gid, details.group_name, details.home
    );
    details
}

fn maybe_chown_target_account_home_dir(config: &Config, target_account_details: &AccountDetails) {
    if !config.chown_home {
        debug!(
            "Skipping changing ownership of '{}' home directory.",
            target_account_details.name
        );
        return;
    }

    // The container may have mounts under the home directory.
    // For example, when using ekidd/rust-musl-builder the user is supposed
    // to mount the a host directory into /home/rust/src.
    //
    // We use 'find' instead of 'chown -R' in order not to cross filesystem
    // boundaries.
    let command_string = format!(
        "find {} -xdev -print0 | xargs -0 -n 128 -x chown {}:{}",
        shell_escape::escape(Cow::from(&target_account_details.home)),
        target_account_details.uid,
        target_account_details.gid
    );
    debug!("Running command with shell: {}", command_string);

    if config.dry_run {
        info!(
            "Dry-run mode on, so not actually running 'chown' on {}.",
            target_account_details.home
        );
        return;
    }

    let result = process::Command::new("/bin/sh")
        .arg("-c")
        .arg(command_string.as_str())
        .status();
    match result {
        Ok(status) => {
            if !status.success() {
                abort!(
                    "Error changing '{}' account: command '{}' failed with exit code {}",
                    target_account_details.name,
                    command_string,
                    status
                        .code()
                        .map(|c| c.to_string())
                        .unwrap_or(String::from("unknown"))
                );
            }
        }
        Err(err) => abort!(
            "Error spawning a shell process for command '{}': {}",
            command_string,
            err
        ),
    };
}

#[derive(Debug, Fail)]
enum ListDirError {
    #[fail(display = "Error reading directory {}: {}", _0, _1)]
    ReadDirError(String, #[cause] io::Error),

    #[fail(display = "Error reading directory entry from {}: {}", _0, _1)]
    ReadDirEntryError(String, #[cause] io::Error),

    #[fail(display = "Error querying file metadata for {}: {}", _0, _1)]
    QueryMetaError(String, #[cause] io::Error),
}

fn list_executable_files_sorted(dir: &PathBuf) -> Result<Vec<PathBuf>, ListDirError> {
    let entries = fs::read_dir(&dir)
        .map_err(|err| ListDirError::ReadDirError(dir.display().to_string(), err))?;
    let mut result = Vec::<PathBuf>::new();

    for entry in entries {
        let entry =
            entry.map_err(|err| ListDirError::ReadDirEntryError(dir.display().to_string(), err))?;
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

fn run_hooks(config: &Config, target_account_details: &AccountDetails) {
    let hooks_dir = PathBuf::from(&config.hooks_dir);
    let hooks = match list_executable_files_sorted(&hooks_dir) {
        Ok(x) => x,
        Err(err) => match &err {
            ListDirError::ReadDirError(_, cause) => {
                if cause.kind() == io::ErrorKind::NotFound {
                    debug!("No hooks found in {}.", hooks_dir.display().to_string());
                    return;
                } else {
                    abort!("Error running hooks: {}", err);
                }
            }
            _ => abort!("Error running hooks: {}", err),
        },
    };

    for hook in hooks {
        debug!("Running hook: {}", hook.display().to_string());

        if config.dry_run {
            info!(
                "Dry-run mode on, so not actually running hook: {}",
                hook.display().to_string()
            );
            continue;
        }

        let target_uid_string = target_account_details.uid.to_string();
        let target_gid_string = target_account_details.uid.to_string();
        let result = process::Command::new(&hook)
            .env("ACU_TARGET_UID", &target_uid_string)
            .env("ACU_TARGET_GID", &target_gid_string)
            .env("ACU_TARGET_USER", &target_account_details.name)
            .env("ACU_TARGET_GROUP", &target_account_details.group_name)
            .env("ACU_TARGET_HOME", &target_account_details.home)
            .status();
        match result {
            Ok(status) => {
                if !status.success() {
                    abort!(
                        "Error running hook {}: command failed with exit code {}",
                        hook.display().to_string(),
                        status
                            .code()
                            .map(|c| c.to_string())
                            .unwrap_or(String::from("unknown"))
                    );
                }
            }
            Err(err) => abort!(
                "Error spawning a process for hook {}: {}",
                hook.display().to_string(),
                err
            ),
        }
    }
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
fn change_supplementary_groups(target_account_details: &AccountDetails) {
    let user_c = CString::new(target_account_details.name.as_bytes()).unwrap_or_else(|err| {
        abort!(
            "Error changing process supplementary groups: error allocating a C string: {}",
            err
        );
    });
    unistd::initgroups(&user_c, target_account_details.gid).unwrap_or_else(|err| {
        abort!("Error changing process supplementary groups: {}", err);
    });
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn change_supplementary_groups(_target_account_details: &AccountDetails) {
    // Not supported by nix crate
}

fn change_user(target_account_details: &AccountDetails) {
    if !unistd::geteuid().is_root() {
        info!("No root privileges. Not changing process UID/GID.");
        return;
    }

    debug!(
        "Setting process supplementary groups to those belonging to group '{}' (GID {}).",
        target_account_details.group_name, target_account_details.gid
    );
    change_supplementary_groups(target_account_details);

    debug!(
        "Setting process group to '{}' (GID {}).",
        target_account_details.group_name, target_account_details.gid
    );
    unistd::setgid(target_account_details.gid).unwrap_or_else(|err| {
        abort!(
            "Error changing process GID to {}: {}",
            target_account_details.gid,
            err
        );
    });

    debug!(
        "Setting process user to '{}' (UID {}).",
        target_account_details.name, target_account_details.uid
    );
    unistd::setuid(target_account_details.uid).unwrap_or_else(|err| {
        abort!(
            "Error changing process UID to {}: {}",
            target_account_details.uid,
            err
        );
    });;

    env::set_var("USER", &target_account_details.name);
    env::set_var("LOGNAME", &target_account_details.name);
    env::set_var("SHELL", &target_account_details.shell);
    env::set_var("HOME", &target_account_details.home);
}

fn maybe_execute_next_command(target_account_details: &AccountDetails) {
    let args: Vec<OsString> = env::args_os().collect();

    if args.len() > 1 {
        fn format_args() -> String {
            env::args().skip(1).collect::<Vec<String>>().join(" ")
        }

        debug!(
            "Executing command specified by CLI arguments: {}",
            format_args()
        );

        let exec_args = args.iter().skip(1).map(|arg| {
            CString::new(arg.clone().into_vec()).unwrap_or_else(|err| {
                abort!(
                    "Error executing command '{}': error allocating C string: {}",
                    format_args(),
                    err
                );
            })
        });
        let exec_args: Vec<CString> = exec_args.collect();

        unistd::execvp(&exec_args[0], &exec_args).unwrap_or_else(|err| {
            abort!("Error executing command '{}': {}", format_args(), err);
        });
    } else if unistd::getpid().as_raw() == 1 {
        debug!(
            "We are PID 1, and no CLI arguments provided, so executing shell: {}",
            target_account_details.shell
        );
        let shell = CString::new(target_account_details.shell.clone()).unwrap_or_else(|err| {
            abort!(
                "Error executing command '{}': error allocating C string: {}",
                target_account_details.shell,
                err
            );
        });
        unistd::execvp(&shell.clone(), &vec![shell]).unwrap_or_else(|err| {
            abort!(
                "Error executing command '{}': {}",
                target_account_details.shell,
                err
            );
        });
    } else {
        debug!("We are not PID 1, and no CLI arguments provided, so exiting without executing next command.");
    }
}

fn main() {
    initialize_logger();
    check_running_allowed();
    let config = load_config();
    reconfigure_logger(&config);
    debug_print_process_privileges();
    drop_setuid_root_bit_on_self_exe_if_necessary();

    let mut using_app_account = false;
    let (target_uid, target_gid) = lookup_target_account_uid_gid_or_abort(&config);
    let app_account_details = lookup_app_account_details_or_abort(&config);
    sanity_check_app_account_details(&config, &app_account_details);
    embrace_setuid_bit_privileges_if_provided();

    if target_uid.is_root() {
        debug!(
            "Target UID ({}) is root. Not modifying '{}' account.",
            target_uid, config.app_account
        );
    } else if target_uid == app_account_details.uid {
        debug!(
            "Target UID ({}) equals '{}' account's UID ({}). Not modifying '{}' account.",
            target_uid, config.app_account, app_account_details.uid, config.app_account,
        );
    } else {
        debug!(
            "Intending to change '{}' account's UID/GID from {}:{} to {}:{}.",
            config.app_account,
            app_account_details.uid,
            app_account_details.gid,
            target_uid,
            target_gid
        );
        ensure_no_account_already_using_target_uid(&config, target_uid);
        ensure_app_account_has_target_uid_and_gid(
            &config,
            &app_account_details,
            target_uid,
            target_gid,
        );
        using_app_account = true;
    }

    if target_gid.as_raw() == 0 {
        debug!(
            "Target GID ({}) is the root group. Not modifying '{}' group.",
            target_gid, app_account_details.group_name,
        );
    } else if target_gid == app_account_details.gid {
        debug!(
            "Target GID ({}) equals '{}' account's GID ({}). Not modifying '{}' group.",
            target_gid, config.app_account, app_account_details.gid, app_account_details.group_name
        );
    } else {
        debug!(
            "Intending to change '{}' group's GID from {} to {}.",
            app_account_details.group_name, app_account_details.gid, target_gid
        );
        ensure_no_group_already_using_target_gid(&config, target_gid);
        ensure_app_group_has_target_gid(&config, &app_account_details, target_gid);
    }

    // The information in here is now stale, so make sure
    // we can't use it anymore.
    std::mem::drop(app_account_details);

    let target_account_details =
        lookup_target_account_details_or_abort(&config, target_uid, target_gid, using_app_account);
    maybe_chown_target_account_home_dir(&config, &target_account_details);
    run_hooks(&config, &target_account_details);
    change_user(&target_account_details);

    maybe_execute_next_command(&target_account_details);
}
