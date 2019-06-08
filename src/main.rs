mod config;
mod os_group;

use config::{load_config, Config};
use failure::Fail;
use log::{debug, error, info, trace};
use nix::unistd;
use nix::unistd::{Gid, Uid};
use os_group::OsGroup;
use pwd;
use pwd::{Passwd, PwdError};
use simple_logger;
use std::os::unix::fs::MetadataExt;
use std::result::Result;
use std::{error, fs, io, process};

fn initialize_logger(config: &Config) {
    simple_logger::init_with_level(config.log_level).unwrap_or_else(|err| {
        eprintln!("Error initializing logger: {}", err);
        process::exit(1);
    });
}

#[derive(Debug, Fail)]
#[fail(display = "Error stat()'ing /proc/1: {}", _0)]
struct Pid1UidGidLookupError(#[cause] io::Error);

fn lookup_pid1_uid_gid(config: &Config) -> Result<(Uid, Gid), Pid1UidGidLookupError> {
    if config.mock_uid.is_some() && config.mock_gid.is_some() {
        Ok((config.mock_uid.unwrap(), config.mock_gid.unwrap()))
    } else if unistd::getpid().as_raw() == 1 {
        Ok((
            config.mock_uid.unwrap_or(unistd::getuid()),
            config.mock_gid.unwrap_or(unistd::getgid()),
        ))
    } else {
        lookup_pid1_uid_gid_from_proc(config)
    }
}

fn lookup_pid1_uid_gid_from_proc(config: &Config) -> Result<(Uid, Gid), Pid1UidGidLookupError> {
    let meta = fs::metadata("/proc/1").map_err(|err| Pid1UidGidLookupError(err))?;
    Ok((
        config.mock_uid.unwrap_or(Uid::from_raw(meta.uid())),
        config.mock_gid.unwrap_or(Gid::from_raw(meta.gid())),
    ))
}

fn lookup_pid1_uid_gid_or_abort(config: &Config) -> (Uid, Gid) {
    let (p1_uid, p1_gid) = lookup_pid1_uid_gid(&config).unwrap_or_else(|err| {
        error!("Error inferring PID 1's UID/GID: {}", err);
        process::exit(1);
    });
    debug!("PID 1's UID:GID = {}:{}", p1_uid, p1_gid);
    (p1_uid, p1_gid)
}

struct AccountDetails {
    uid: Uid,
    gid: Gid,
    group_name: String,
    home: String,
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
    let grp_entry = match OsGroup::from_gid(&gid) {
        Ok(Some(x)) => x,
        Ok(None) => return Err(AccountDetailsLookupError::PrimaryGroupNotFound(gid)),
        Err(err) => return Err(AccountDetailsLookupError::GroupLookupError(err)),
    };

    Ok(AccountDetails {
        uid: config
            .mock_app_account_uid
            .unwrap_or(Uid::from_raw(entry.uid)),
        gid: gid,
        group_name: grp_entry.name,
        home: entry.dir,
    })
}

fn lookup_app_account_details_or_abort(config: &Config) -> AccountDetails {
    let acc_details = lookup_app_account_details(&config).unwrap_or_else(|err| {
        error!(
            "Error looking up UID/GID for OS user account '{}': {}",
            config.app_account, err
        );
        process::exit(1);
    });
    debug!(
        "App account's ('{}') UID:GID = {}:{}",
        config.app_account, acc_details.uid, acc_details.gid,
    );
    acc_details
}

fn sanity_check_app_account_details(config: &Config, app_account_details: &AccountDetails) {
    if app_account_details.uid.is_root() {
        error!(
            "The configured app account ({}) has UID 0 (root). \
             This is not allowed, please configure a different \
             app account.",
            config.app_account
        );
        process::exit(1);
    }
    if app_account_details.gid.as_raw() == 0 {
        error!(
            "The configured app account ({}) belongs to a primary \
             group whose GID is 0 ('{}', the root group). This is not \
             allowed, please configure a different app account.",
            config.app_account, app_account_details.group_name
        );
        process::exit(1);
    }
}

fn lookup_account_with_uid(uid: &Uid) -> Result<Option<Passwd>, Box<dyn error::Error>> {
    match Passwd::from_uid(uid.as_raw()) {
        Some(i) => Ok(Some(i)),
        None => Ok(None),
    }
}

fn find_unused_uid(min_uid: &Uid) -> Option<Uid> {
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

fn find_unused_gid(min_gid: &Gid) -> Result<Option<Gid>, os_group::Error> {
    const MAX_POSSIBLE_GID: u64 = 0xFFFF;
    let min_gid = min_gid.as_raw();
    let max_gid = (min_gid as u64 + MAX_POSSIBLE_GID).min(MAX_POSSIBLE_GID) as u32;

    for gid in min_gid + 1..max_gid {
        match OsGroup::from_gid(&Gid::from_raw(gid)) {
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
type EtcPasswdEntryModifier = Fn(&mut Vec<BinaryString>);

fn modify_etc_passwd(
    dry_run: bool,
    modifier: &EtcPasswdEntryModifier,
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
        Ok(())
    } else {
        trace!(
            "Modifying /etc/passwd to:\n\
             ---- BEGIN PASSWD ----\n\
             {}\
             ---- END PASSWD ----",
            String::from_utf8_lossy(&result)
        );
        fs::write("/etc/passwd", result).map_err(|err| AccountModifyError::PasswdWriteError(err))
    }
}

fn modify_account_uid_gid<'a>(
    config: &Config,
    old_uid: &Uid,
    new_uid: &Uid,
    new_gid: &Gid,
) -> Result<(), AccountModifyError> {
    let old_uid_string = old_uid.to_string();
    let new_uid = new_uid.clone();
    let new_gid = new_gid.clone();
    modify_etc_passwd(config.dry_run, &move |items: &mut Vec<BinaryString>| {
        if items[2] == old_uid_string.as_bytes() {
            items[2] = new_uid.as_raw().to_string().as_bytes().to_vec();
            items[3] = new_gid.as_raw().to_string().as_bytes().to_vec();
        }
    })
}

fn modify_group_gid(
    config: &Config,
    old_gid: &Gid,
    new_gid: &Gid,
) -> Result<(), AccountModifyError> {
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

    let new_gid = new_gid.clone();
    modify_etc_passwd(config.dry_run, &move |items: &mut Vec<BinaryString>| {
        if items[3] == old_gid_string.as_bytes() {
            items[3] = new_gid.as_raw().to_string().as_bytes().to_vec();
        }
    })
}

fn ensure_no_account_already_using_pid1_uid(config: &Config, p1_uid: &Uid) {
    debug!(
        "Checking whether PID 1's UID ({}) is already occupied by an existing account.",
        p1_uid
    );
    match lookup_account_with_uid(&p1_uid) {
        Ok(Some(conflicting_account)) => {
            debug!(
                "PID 1's UID ({}) already occupied by account '{}'. \
                 Will change that account's UID.",
                p1_uid, conflicting_account.name
            );
            let new_uid = find_unused_uid(&p1_uid).unwrap_or_else(|| {
                error!(
                    "Error changing conflicting account '{}': \
                     cannot find an unused UID that's larger than {}",
                    conflicting_account.name, p1_uid
                );
                process::exit(1);
            });

            debug!(
                "Changing conflicting account '{}' UID: {} -> {}",
                conflicting_account.name, p1_uid, new_uid
            );
            modify_account_uid_gid(
                &config,
                &p1_uid,
                &new_uid,
                &Gid::from_raw(conflicting_account.gid),
            )
            .unwrap_or_else(|err| {
                error!(
                    "Error changing conflicting account '{}' UID from {} to {}: {}",
                    conflicting_account.name, p1_uid, new_uid, err
                );
                process::exit(1);
            });
        }
        Ok(None) => debug!(
            "PID 1's UID ({}) not already occupied by existing account.",
            p1_uid
        ),
        Err(err) => {
            error!(
                "Error checking whether PID 1's UID ({}) \
                 is already occupied by an existing account: {}",
                p1_uid, err
            );
            process::exit(1);
        }
    };
}

fn ensure_app_account_has_pid1_uid_and_gid(
    config: &Config,
    app_account_details: &AccountDetails,
    p1_uid: &Uid,
    p1_gid: &Gid,
) {
    debug!(
        "Changing account '{}' UID/GID ({}:{}) to match PID 1's UID/GID ({}:{}).",
        config.app_account, app_account_details.uid, app_account_details.gid, p1_uid, p1_gid
    );
    modify_account_uid_gid(config, &app_account_details.uid, p1_uid, p1_gid).unwrap_or_else(
        |err| {
            error!(
                "Error changing account '{}' UID/GID from {}:{} to {}:{}: {}",
                config.app_account,
                app_account_details.uid,
                app_account_details.gid,
                p1_uid,
                p1_gid,
                err
            );
            process::exit(1);
        },
    );
}

fn ensure_no_group_already_using_pid1_gid(config: &Config, p1_gid: &Gid) {
    debug!(
        "Checking whether PID 1's GID ({}) is already occupied by an existing group.",
        p1_gid
    );
    match OsGroup::from_gid(p1_gid) {
        Ok(Some(conflicting_group)) => {
            debug!(
                "PID 1's GID ({}) already occupied by group '{}'. \
                 Will change that group's GID.",
                p1_gid, conflicting_group.name
            );
            let new_gid = find_unused_gid(&p1_gid).unwrap_or_else(|err| {
                error!(
                    "Error changing conflicting group '{}': \
                     error finding an unused GID that's larger \
                     than {}: {}",
                    conflicting_group.name, p1_gid, err
                );
                process::exit(1);
            });
            let new_gid = new_gid.unwrap_or_else(|| {
                error!(
                    "Error changing conflicting group '{}': \
                     cannot find an unused GID that's larger than {}",
                    conflicting_group.name, p1_gid
                );
                process::exit(1);
            });

            debug!(
                "Changing conflicting group '{}' GID: {} -> {}",
                conflicting_group.name, p1_gid, new_gid
            );
            modify_group_gid(&config, &p1_gid, &new_gid).unwrap_or_else(|err| {
                error!(
                    "Error changing conflicting group '{}' GID from {} to {}: {}",
                    conflicting_group.name, p1_gid, new_gid, err
                );
                process::exit(1);
            });
        }
        Ok(None) => debug!(
            "PID 1's GID ({}) not already occupied by existing group.",
            p1_gid
        ),
        Err(err) => {
            error!(
                "Error checking whether PID 1's GID ({}) \
                 is already occupied by an existing group: {}",
                p1_gid, err
            );
            process::exit(1);
        }
    };
}

fn ensure_app_group_has_pid1_gid(
    config: &Config,
    app_account_details: &AccountDetails,
    p1_gid: &Gid,
) {
    debug!(
        "Changing group '{}' GID ({}) to match PID 1's GID ({}).",
        app_account_details.group_name, app_account_details.gid, p1_gid
    );
    modify_group_gid(&config, &app_account_details.gid, &p1_gid).unwrap_or_else(|err| {
        error!(
            "Error changing group '{}' GID from {} to {}: {}",
            app_account_details.group_name, app_account_details.gid, p1_gid, err
        );
        process::exit(1);
    });
}

fn main() {
    let config = load_config();
    initialize_logger(&config);

    let (p1_uid, p1_gid) = lookup_pid1_uid_gid_or_abort(&config);
    let app_account_details = lookup_app_account_details_or_abort(&config);
    sanity_check_app_account_details(&config, &app_account_details);

    if p1_uid.is_root() {
        debug!(
            "PID 1's UID ({}) is root. Not modifying '{}' account.",
            p1_uid, config.app_account
        );
    } else if p1_uid == app_account_details.uid {
        debug!(
            "PID 1's UID ({}) equals '{}' account's UID ({}). Not modifying '{}' account.",
            p1_uid, config.app_account, app_account_details.uid, config.app_account,
        );
    } else {
        debug!(
            "Intending to change '{}' account's UID/GID from {}:{} to {}:{}.",
            config.app_account, app_account_details.uid, app_account_details.gid, p1_uid, p1_gid
        );
        ensure_no_account_already_using_pid1_uid(&config, &p1_uid);
        ensure_app_account_has_pid1_uid_and_gid(&config, &app_account_details, &p1_uid, &p1_gid);
    }

    if p1_gid.as_raw() == 0 {
        debug!(
            "PID 1's GID ({}) is the root group. Not modifying '{}' group.",
            p1_gid, app_account_details.group_name,
        );
    } else if p1_gid == app_account_details.gid {
        debug!(
            "PID 1's GID ({}) equals '{}' account's GID ({}). Not modifying '{}' group.",
            p1_gid, config.app_account, app_account_details.gid, app_account_details.group_name
        );
    } else {
        debug!(
            "Intending to change '{}' group's GID from {} to {}.",
            app_account_details.group_name, app_account_details.gid, p1_gid
        );
        ensure_no_group_already_using_pid1_gid(&config, &p1_gid);
        ensure_app_group_has_pid1_gid(&config, &app_account_details, &p1_gid);
    }

    /* chown_app_account_home(&config, &app_account_details);
    run_hooks(config.hooks_dir);
    change_user(uid, gid);

    maybe_execute_next_command(); */
}
