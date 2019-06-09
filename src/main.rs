mod abort;
mod config;
mod os_group;
mod simple_logger;

use config::{load_config, Config};
use failure::Fail;
use log::{debug, error, info, trace, warn, Level};
use nix::unistd::{self, Gid, Uid};
use os_group::OsGroup;
use pwd::{self, Passwd, PwdError};
use std::os::unix::fs::MetadataExt;
use std::result::Result;
use std::{env, error, fs, io, path, process};

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
                warn!("Error stat()ing /proc/self/exe: {}", err);
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
             - Hint: set AP1U_ALLOW_NON_ROOT=1 to force running this \
             program despite not having root privileges.",
            self_exe_desc,
            self_exe_path_str,
            self_exe_path_str
        );
    }
}

fn get_self_exe_path() -> io::Result<path::PathBuf> {
    fs::read_link("/proc/self/exe")
}

fn allow_non_root() -> bool {
    match env::var("AP1U_ALLOW_NON_ROOT") {
        Ok(val) => config::parse_bool_str(&val).unwrap_or(false),
        Err(env::VarError::NotPresent) => false,
        Err(env::VarError::NotUnicode(_)) => false,
    }
}

fn reconfigure_logger(config: &Config) {
    log::set_max_level(config.log_level.to_level_filter());
}

fn drop_setuid_bit_on_self_exe_if_necessary() {
    // TODO
}

#[derive(Clone)]
struct AccountDetails {
    uid: Uid,
    gid: Gid,
    group_name: String,
}

#[derive(Debug, Fail)]
enum AccountDetailsLookupError {
    #[fail(display = "Error stat()'ing /proc/1: {}", _0)]
    Proc1StatError(#[cause] io::Error),

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

fn lookup_target_account_details(
    config: &Config,
) -> Result<AccountDetails, AccountDetailsLookupError> {
    let uid: Uid;
    let gid: Gid;

    if config.target_uid.is_some() && config.target_gid.is_some() {
        debug!("Using target UID/GID specified by configuration.");
        uid = config.target_uid.unwrap();
        gid = config.target_gid.unwrap();
    } else {
        if config.target_uid.is_some() {
            debug!("Using target UID specified by configuration.");
        } else {
            debug!("Using target GID specified by configuration.");
        }

        if unistd::getpid().as_raw() == 1 {
            uid = config.target_uid.unwrap_or(unistd::getuid());
            gid = config.target_gid.unwrap_or(unistd::getgid());
        } else {
            debug!("Looking up target UID/GID by querying /proc/1.");
            let (x, y) = lookup_target_uid_gid_from_proc(config)?;
            uid = config.target_uid.unwrap_or(x);
            gid = config.target_gid.unwrap_or(y);
        }
    }

    let grp_entry = match OsGroup::from_gid(&gid) {
        Ok(Some(x)) => x,
        Ok(None) => return Err(AccountDetailsLookupError::PrimaryGroupNotFound(gid)),
        Err(err) => return Err(AccountDetailsLookupError::GroupLookupError(err)),
    };

    Ok(AccountDetails {
        uid: uid,
        gid: gid,
        group_name: grp_entry.name,
    })
}

fn lookup_target_uid_gid_from_proc(
    config: &Config,
) -> Result<(Uid, Gid), AccountDetailsLookupError> {
    let meta =
        fs::metadata("/proc/1").map_err(|err| AccountDetailsLookupError::Proc1StatError(err))?;
    Ok((
        config.target_uid.unwrap_or(Uid::from_raw(meta.uid())),
        config.target_gid.unwrap_or(Gid::from_raw(meta.gid())),
    ))
}

fn lookup_target_account_details_or_abort(config: &Config) -> AccountDetails {
    let details = lookup_target_account_details(&config).unwrap_or_else(|err| {
        abort!("Error looking up target UID/GID: {}", err);
    });
    debug!("Target UID/GID = {}:{}", details.uid, details.gid);
    details
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
    modify_etc_passwd(config.dry_run, |items: &mut Vec<BinaryString>| {
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

    modify_etc_passwd(config.dry_run, |items: &mut Vec<BinaryString>| {
        if items[3] == old_gid_string.as_bytes() {
            items[3] = new_gid.as_raw().to_string().as_bytes().to_vec();
        }
    })
}

fn ensure_no_account_already_using_target_uid(config: &Config, target_uid: &Uid) {
    debug!(
        "Checking whether the target UID ({}) is already occupied by an existing account.",
        target_uid
    );
    match lookup_account_with_uid(&target_uid) {
        Ok(Some(conflicting_account)) => {
            debug!(
                "Target UID ({}) already occupied by account '{}'. \
                 Will change that account's UID.",
                target_uid, conflicting_account.name
            );
            let new_uid = find_unused_uid(&target_uid).unwrap_or_else(|| {
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
                &target_uid,
                &new_uid,
                &Gid::from_raw(conflicting_account.gid),
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
    target_account_details: &AccountDetails,
) {
    debug!(
        "Changing account '{}' UID/GID ({}:{}) to match target UID/GID ({}:{}).",
        config.app_account,
        app_account_details.uid,
        app_account_details.gid,
        target_account_details.uid,
        target_account_details.gid
    );
    modify_account_uid_gid(
        config,
        &app_account_details.uid,
        &target_account_details.uid,
        &target_account_details.gid,
    )
    .unwrap_or_else(|err| {
        abort!(
            "Error changing account '{}' UID/GID from {}:{} to {}:{}: {}",
            config.app_account,
            app_account_details.uid,
            app_account_details.gid,
            target_account_details.uid,
            target_account_details.gid,
            err
        );
    });
}

fn ensure_no_group_already_using_target_gid(config: &Config, target_gid: &Gid) {
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
            let new_gid = find_unused_gid(&target_gid).unwrap_or_else(|err| {
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
            modify_group_gid(&config, &target_gid, &new_gid).unwrap_or_else(|err| {
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
    target_gid: &Gid,
) {
    debug!(
        "Changing group '{}' GID ({}) to match the target GID ({}).",
        app_account_details.group_name, app_account_details.gid, target_gid
    );
    modify_group_gid(&config, &app_account_details.gid, &target_gid).unwrap_or_else(|err| {
        abort!(
            "Error changing group '{}' GID from {} to {}: {}",
            app_account_details.group_name,
            app_account_details.gid,
            target_gid,
            err
        );
    });
}

fn main() {
    initialize_logger();
    check_running_allowed();
    drop_setuid_bit_on_self_exe_if_necessary();
    let config = load_config();
    reconfigure_logger(&config);

    let target_account_details = lookup_target_account_details_or_abort(&config);
    let mut app_account_details = lookup_app_account_details_or_abort(&config);
    sanity_check_app_account_details(&config, &app_account_details);

    if target_account_details.uid.is_root() {
        debug!(
            "Target UID ({}) is root. Not modifying '{}' account.",
            target_account_details.uid, config.app_account
        );
    } else if target_account_details.uid == app_account_details.uid {
        debug!(
            "Target UID ({}) equals '{}' account's UID ({}). Not modifying '{}' account.",
            target_account_details.uid,
            config.app_account,
            app_account_details.uid,
            config.app_account,
        );
    } else {
        debug!(
            "Intending to change '{}' account's UID/GID from {}:{} to {}:{}.",
            config.app_account,
            app_account_details.uid,
            app_account_details.gid,
            target_account_details.uid,
            target_account_details.gid
        );
        ensure_no_account_already_using_target_uid(&config, &target_account_details.uid);
        ensure_app_account_has_target_uid_and_gid(
            &config,
            &app_account_details,
            &target_account_details,
        );
        app_account_details = target_account_details.clone();
    }

    if target_account_details.gid.as_raw() == 0 {
        debug!(
            "Target GID ({}) is the root group. Not modifying '{}' group.",
            target_account_details.gid, app_account_details.group_name,
        );
    } else if target_account_details.gid == app_account_details.gid {
        debug!(
            "Target GID ({}) equals '{}' account's GID ({}). Not modifying '{}' group.",
            target_account_details.gid,
            config.app_account,
            app_account_details.gid,
            app_account_details.group_name
        );
    } else {
        debug!(
            "Intending to change '{}' group's GID from {} to {}.",
            app_account_details.group_name, app_account_details.gid, target_account_details.gid
        );
        ensure_no_group_already_using_target_gid(&config, &target_account_details.gid);
        ensure_app_group_has_target_gid(&config, &app_account_details, &target_account_details.gid);
    }

    /* chown_target_account_home_dir(&config, &target_uid, &target_account_details.gid);
    run_hooks(config.hooks_dir);
    change_user(target_uid, target_account_details.gid);

    maybe_execute_next_command(); */
}

/*fn chown_target_account_home(config: &Config, target_uid: &Uid, target_gid: &Gid, app_account_details: &AccountDetails) {
    //let account_details = {
//        if target_uid == app_
//    };
    /* = Passwd::from_uid(target_uid).unwrap_or_else(|err| {
        error!("Error looking up home directory for target UID ({}): ");
        process::exit(1);
    }); */
} */
