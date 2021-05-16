mod abort;
mod config;
mod simple_logger;
mod system_calls;
mod utils;

use config::{load_config, Config};
use libc;
use log::{debug, error, info, trace, warn, Level};
use nix::unistd::{self, Gid, Uid};
use std::ffi::{CString, NulError, OsString};
use std::os::unix::{ffi::OsStrExt, ffi::OsStringExt, fs::MetadataExt, fs::PermissionsExt};
use std::{env, fs, io, path::Path, path::PathBuf, process, result::Result};
use thiserror::Error;
use utils::{AccountDetails, AccountDetailsLookupError};

fn initialize_logger() {
    simple_logger::init_with_level(Level::Info).unwrap_or_else(|err| {
        eprintln!("*** ERROR initializing logger: {}", err);
        process::exit(1);
    });
}

// During the course of this program we shell out to external tools
// before we've dropped root privileges. So we set PATH to a safe default
// in order to prevent shelling out to malicious tools.
fn set_path_to_safe_default() -> Option<OsString> {
    let old_path = env::var_os("PATH");
    env::set_var(
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    );
    return old_path;
}

// Since this program is supposed to be run with the setuid root biit,
// we must only allow it to be run in very specific circumstances
// that are deemed safe.
fn check_running_allowed() {
    if unistd::geteuid().is_root() {
        if unistd::getpid().as_raw() != 1
            && !is_child_of_pid1_docker_init()
            && !unistd::getuid().is_root()
        {
            abort!(
                "This program may only be run when one \
                 of the following conditions apply:\n\
                 \n \
                 - This program is run as PID 1.\n \
                 - This program is a child of PID 1, and PID 1 is the Docker \
                 init process (/dev/init, /(usr/)sbin/docker-init).\n \
                 - This program is run with root privileges (but not \
                 via the setuid root bit)."
            );
        }
    } else if !allow_non_root() {
        // We don't have the setuid root bit set.

        let self_exe_path = utils::get_self_exe_path();
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
             - Hint: set MHF_ALLOW_NON_ROOT=1 to force running this \
             program despite not having root privileges.",
            self_exe_desc,
            self_exe_path_str,
            self_exe_path_str
        );
    }
}

fn is_child_of_pid1_docker_init() -> bool {
    if unistd::getppid().as_raw() != 1 {
        return false;
    }

    match utils::read_link_by_shelling_out(Path::new("/proc/1/exe")) {
        Ok(path) => {
            path.as_path() == Path::new("/dev/init")
                || path.as_path() == Path::new("/sbin/docker-init")
                || path.as_path() == Path::new("/usr/sbin/docker-init")
        }
        Err(utils::ReadLinkError::CommandFailed(status)) => {
            warn!(
                "Error determining whether PID 1 is the Docker init process \
                 /dev/init: subprocess 'readlink /proc/1/exe' failed with code {}",
                status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or(String::from("unknown"))
            );
            false
        }
        Err(utils::ReadLinkError::IOError(io_err)) => {
            warn!(
                "Error determining whether PID 1 is the Docker init process \
                 /dev/init: error reading from subprocess 'readlink /proc/1/exe': {}",
                io_err
            );
            false
        }
    }
}

fn allow_non_root() -> bool {
    match env::var("MHF_ALLOW_NON_ROOT") {
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
    let path = utils::get_self_exe_path().unwrap_or_else(|err| {
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

#[derive(Error, Debug)]
#[error("Error stat()'ing /proc/1: {0}")]
struct Proc1StatError(#[from] io::Error);

fn lookup_host_account_uid_gid(config: &Config) -> Result<(Uid, Gid), Proc1StatError> {
    if config.host_uid.is_some() && config.host_gid.is_some() {
        debug!("Using host UID/GID specified by configuration.");
        return Ok((config.host_uid.unwrap(), config.host_gid.unwrap()));
    }

    if config.host_uid.is_some() {
        debug!("Using host UID specified by configuration.");
    } else if config.host_gid.is_some() {
        debug!("Using host GID specified by configuration.");
    }

    if unistd::getpid().as_raw() == 1 {
        Ok((
            config.host_uid.unwrap_or(unistd::getuid()),
            config.host_gid.unwrap_or(unistd::getgid()),
        ))
    } else {
        debug!("Looking up host account UID/GID by querying /proc/1.");
        lookup_host_account_uid_gid_from_proc(config)
    }
}

fn lookup_host_account_uid_gid_from_proc(config: &Config) -> Result<(Uid, Gid), Proc1StatError> {
    let meta = fs::metadata("/proc/1").map_err(|err| Proc1StatError(err))?;
    Ok((
        config.host_uid.unwrap_or(Uid::from_raw(meta.uid())),
        config.host_gid.unwrap_or(Gid::from_raw(meta.gid())),
    ))
}

fn lookup_host_account_uid_gid_or_abort(config: &Config) -> (Uid, Gid) {
    let (uid, gid) = lookup_host_account_uid_gid(&config).unwrap_or_else(|err| {
        abort!("Error looking up host account UID/GID: {}", err);
    });
    debug!("Host account UID/GID = {}:{}", uid, gid);
    (uid, gid)
}

fn lookup_app_account_details(
    config: &Config,
) -> Result<AccountDetails, AccountDetailsLookupError> {
    let entry = match unistd::User::from_name(config.app_account.as_str()) {
        Ok(Some(x)) => x,
        Ok(None) => return Err(AccountDetailsLookupError::UserNotFound),
        Err(err) => return Err(AccountDetailsLookupError::UserLookupError(err)),
    };

    let gid = config.mock_app_account_gid.unwrap_or(entry.gid);
    let grp_entry = match unistd::Group::from_gid(gid) {
        Ok(Some(x)) => x,
        Ok(None) => return Err(AccountDetailsLookupError::PrimaryGroupNotFound(gid)),
        Err(err) => return Err(AccountDetailsLookupError::GroupLookupError(err)),
    };

    Ok(AccountDetails {
        uid: config.mock_app_account_uid.unwrap_or(entry.uid),
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

#[derive(Error, Debug)]
enum AccountModifyError {
    #[error("Error reading /etc/passwd: {0}")]
    PasswdReadError(#[source] io::Error),

    #[error("Error writing /etc/passwd: {0}")]
    PasswdWriteError(#[source] io::Error),

    #[error("Error reading /etc/group: {0}")]
    GroupReadError(#[source] io::Error),

    #[error("Error writing /etc/group: {0}")]
    GroupWriteError(#[source] io::Error),
}

fn modify_etc_passwd(
    dry_run: bool,
    modifier: impl FnMut(&mut Vec<Vec<u8>>),
) -> Result<(), AccountModifyError> {
    let content =
        fs::read("/etc/passwd").map_err(|err| AccountModifyError::PasswdReadError(err))?;
    let result = utils::modify_etc_passwd_contents(content.as_slice(), modifier);
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
    modify_etc_passwd(config.dry_run, |items: &mut Vec<Vec<u8>>| {
        if items[2] == old_uid_string.as_bytes() {
            items[2] = new_uid.to_string().as_bytes().to_vec();
            items[3] = new_gid.to_string().as_bytes().to_vec();
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

        let mut items: Vec<Vec<u8>> = line
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

    let mut result = lines.collect::<Vec<Vec<u8>>>().join(&(b'\n'));
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

    modify_etc_passwd(config.dry_run, |items: &mut Vec<Vec<u8>>| {
        if items[3] == old_gid_string.as_bytes() {
            items[3] = new_gid.as_raw().to_string().as_bytes().to_vec();
        }
    })
}

fn ensure_no_account_already_using_host_uid(config: &Config, host_uid: Uid) {
    debug!(
        "Checking whether the host UID ({}) is already occupied by an existing account.",
        host_uid
    );
    match unistd::User::from_uid(host_uid) {
        Ok(Some(conflicting_account)) => {
            debug!(
                "Host UID ({}) already occupied by account '{}'. \
                 Will change that account's UID.",
                host_uid, conflicting_account.name
            );
            let new_uid = match utils::find_unused_uid(host_uid) {
                Ok(Some(uid)) => uid,
                Ok(None) =>
                    abort!(
                        "Error changing conflicting account '{}': \
                            cannot find an unused UID that's larger than {}",
                        conflicting_account.name,
                        host_uid
                    ),
                Err(err) =>
                    abort!(
                        "Error changing conflicting account '{}': \
                         an error occurred while trying to find an unused UID that's larger than {}: {}",
                        conflicting_account.name,
                        host_uid,
                        err
                    ),
            };

            debug!(
                "Changing conflicting account '{}' UID: {} -> {}",
                conflicting_account.name, host_uid, new_uid
            );
            modify_account_uid_gid(&config, host_uid, new_uid, conflicting_account.gid)
                .unwrap_or_else(|err| {
                    abort!(
                        "Error changing conflicting account '{}' UID from {} to {}: {}",
                        conflicting_account.name,
                        host_uid,
                        new_uid,
                        err
                    );
                });
        }
        Ok(None) => debug!(
            "Host UID ({}) not already occupied by existing account.",
            host_uid
        ),
        Err(err) => abort!(
            "Error checking whether the host UID ({}) \
                 is already occupied by an existing account: {}",
            host_uid,
            err
        ),
    };
}

fn ensure_app_account_has_host_uid_and_gid(
    config: &Config,
    app_account_details: &AccountDetails,
    host_uid: Uid,
    host_gid: Gid,
) {
    debug!(
        "Changing account '{}' UID/GID ({}:{}) to match host UID/GID ({}:{}).",
        config.app_account, app_account_details.uid, app_account_details.gid, host_uid, host_gid
    );
    modify_account_uid_gid(config, app_account_details.uid, host_uid, host_gid).unwrap_or_else(
        |err| {
            abort!(
                "Error changing account '{}' UID/GID from {}:{} to {}:{}: {}",
                config.app_account,
                app_account_details.uid,
                app_account_details.gid,
                host_uid,
                host_gid,
                err
            );
        },
    );
}

fn ensure_no_group_already_using_host_gid(config: &Config, host_gid: Gid) {
    debug!(
        "Checking whether the host GID ({}) is already occupied by an existing group.",
        host_gid
    );
    match unistd::Group::from_gid(host_gid) {
        Ok(Some(conflicting_group)) => {
            debug!(
                "Host GID ({}) already occupied by group '{}'. \
                 Will change that group's GID.",
                host_gid, conflicting_group.name
            );
            let new_gid = utils::find_unused_gid(host_gid).unwrap_or_else(|err| {
                abort!(
                    "Error changing conflicting group '{}': \
                     error finding an unused GID that's larger \
                     than {}: {}",
                    conflicting_group.name,
                    host_gid,
                    err
                );
            });
            let new_gid = new_gid.unwrap_or_else(|| {
                abort!(
                    "Error changing conflicting group '{}': \
                     cannot find an unused GID that's larger than {}",
                    conflicting_group.name,
                    host_gid
                );
            });

            debug!(
                "Changing conflicting group '{}' GID: {} -> {}",
                conflicting_group.name, host_gid, new_gid
            );
            modify_group_gid(&config, host_gid, new_gid).unwrap_or_else(|err| {
                abort!(
                    "Error changing conflicting group '{}' GID from {} to {}: {}",
                    conflicting_group.name,
                    host_gid,
                    new_gid,
                    err
                );
            });
        }
        Ok(None) => debug!(
            "Host GID ({}) not already occupied by existing group.",
            host_gid
        ),
        Err(err) => abort!(
            "Error checking whether the host GID ({}) \
                    is already occupied by an existing group: {}",
            host_gid,
            err
        ),
    };
}

fn ensure_app_group_has_host_gid(
    config: &Config,
    app_account_details: &AccountDetails,
    host_gid: Gid,
) {
    debug!(
        "Changing group '{}' GID ({}) to match the host GID ({}).",
        app_account_details.group_name, app_account_details.gid, host_gid
    );
    modify_group_gid(&config, app_account_details.gid, host_gid).unwrap_or_else(|err| {
        abort!(
            "Error changing group '{}' GID from {} to {}: {}",
            app_account_details.group_name,
            app_account_details.gid,
            host_gid,
            err
        );
    });
}

fn lookup_target_account_details_or_abort(
    config: &Config,
    host_uid: Uid,
    host_gid: Gid,
    using_app_account: bool,
) -> AccountDetails {
    let details = utils::lookup_account_details(host_uid, host_gid).unwrap_or_else(|err| {
        if using_app_account {
            abort!(
                "Error looking up app account ('{}') details (UID/GID {}:{}): {}",
                config.app_account,
                host_uid,
                host_gid,
                err
            );
        } else {
            abort!(
                "Error looking up OS account details for UID/GID {}:{}: {}",
                host_uid,
                host_gid,
                err
            );
        }
    });
    debug!(
        "Target account is '{}' (UID/GID = {}:{}, group = {}, home = {}).",
        details.name,
        host_uid,
        host_gid,
        details.group_name,
        details.home.display()
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

    debug!(
        "Recursively changing ownership of '{}' home directory: {}",
        target_account_details.name,
        target_account_details.home.display()
    );
    if config.dry_run {
        info!("Dry-run mode on, so not actually running changing home directory ownership.");
        return;
    }

    let result = utils::chown_dir_recursively_no_fs_boundary_crossing(
        target_account_details.home.as_path(),
        target_account_details.uid,
        target_account_details.gid,
    );
    match result {
        Ok(_) => (),
        Err(utils::ChownError::PathInvalidUTF8) => abort!(
            "Error changing '{}' account: home directory path '{}' is not valid unicode",
            target_account_details.name,
            target_account_details.home.display()
        ),
        Err(utils::ChownError::CommandFailed(status, command)) => abort!(
            "Error changing '{}' account: command '{}' failed with exit code {}",
            target_account_details.name,
            command,
            status
                .code()
                .map(|c| c.to_string())
                .unwrap_or(String::from("unknown"))
        ),
        Err(utils::ChownError::IOError(io_err, command)) => abort!(
            "Error changing '{}' account: error spawning a shell process for command '{}': {}",
            target_account_details.name,
            command,
            io_err
        ),
    }
}

fn run_hooks(config: &Config, host_account_details: &AccountDetails) {
    let hooks_dir = PathBuf::from(&config.hooks_dir);
    let hooks = match utils::list_executable_files_sorted(&hooks_dir) {
        Ok(x) => x,
        Err(err) => match &err {
            utils::ListDirError::ReadDirError(_, cause) => {
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

        let host_uid_string = host_account_details.uid.to_string();
        let host_gid_string = host_account_details.uid.to_string();
        let result = process::Command::new(&hook)
            .env("MHF_HOST_UID", &host_uid_string)
            .env("MHF_HOST_GID", &host_gid_string)
            .env("MHF_HOST_USER", &host_account_details.name)
            .env("MHF_HOST_GROUP", &host_account_details.group_name)
            .env("MHF_HOST_HOME", &host_account_details.home)
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
fn change_supplementary_groups(host_account_details: &AccountDetails) {
    let user_c = CString::new(host_account_details.name.as_bytes()).unwrap_or_else(|err| {
        abort!(
            "Error changing process supplementary groups: error allocating a C string: {}",
            err
        );
    });
    unistd::initgroups(&user_c, host_account_details.gid).unwrap_or_else(|err| {
        abort!("Error changing process supplementary groups: {}", err);
    });
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
fn change_supplementary_groups(_host_account_details: &AccountDetails) {
    // Not supported by nix crate
}

fn change_user(host_account_details: &AccountDetails) {
    if !unistd::geteuid().is_root() {
        info!("No root privileges. Not changing process UID/GID.");
        return;
    }

    debug!(
        "Setting process supplementary groups to those belonging to group '{}' (GID {}).",
        host_account_details.group_name, host_account_details.gid
    );
    change_supplementary_groups(host_account_details);

    debug!(
        "Setting process group to '{}' (GID {}).",
        host_account_details.group_name, host_account_details.gid
    );
    unistd::setgid(host_account_details.gid).unwrap_or_else(|err| {
        abort!(
            "Error changing process GID to {}: {}",
            host_account_details.gid,
            err
        );
    });

    debug!(
        "Setting process user to '{}' (UID {}).",
        host_account_details.name, host_account_details.uid
    );
    unistd::setuid(host_account_details.uid).unwrap_or_else(|err| {
        abort!(
            "Error changing process UID to {}: {}",
            host_account_details.uid,
            err
        );
    });

    env::set_var("USER", &host_account_details.name);
    env::set_var("LOGNAME", &host_account_details.name);
    env::set_var("SHELL", &host_account_details.shell);
    env::set_var("HOME", &host_account_details.home);
}

fn path_to_cstring(path: &Path) -> Result<CString, NulError> {
    let path_data = path.as_os_str().as_bytes();
    return CString::new(Vec::from(path_data));
}

fn restore_old_path(old_path: Option<OsString>) {
    if old_path.is_some() {
        env::set_var("PATH", old_path.unwrap());
    }
}

fn maybe_execute_next_command(host_account_details: &AccountDetails) {
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
            host_account_details.shell.display()
        );
        let shell = match path_to_cstring(host_account_details.shell.as_path()) {
            Ok(x) => x,
            Err(NulError { .. }) => abort!(
                "Error executing command '{}': shell path name contains a forbidden null byte",
                host_account_details.shell.display(),
            ),
        };
        unistd::execvp(&shell.clone(), &vec![shell]).unwrap_or_else(|err| {
            abort!(
                "Error executing command '{}': {}",
                host_account_details.shell.display(),
                err
            );
        });
    } else {
        debug!("We are not PID 1, and no CLI arguments provided, so exiting without executing next command.");
    }
}

fn main() {
    initialize_logger();
    let old_path = set_path_to_safe_default();
    check_running_allowed();
    let config = load_config();
    reconfigure_logger(&config);
    debug_print_process_privileges();
    drop_setuid_root_bit_on_self_exe_if_necessary();

    let mut using_app_account = false;
    let (host_uid, host_gid) = lookup_host_account_uid_gid_or_abort(&config);
    let app_account_details = lookup_app_account_details_or_abort(&config);
    sanity_check_app_account_details(&config, &app_account_details);
    embrace_setuid_bit_privileges_if_provided();

    if host_uid.is_root() {
        debug!(
            "Host account UID ({}) is root. Not modifying '{}' account.",
            host_uid, config.app_account
        );
    } else if host_uid == app_account_details.uid {
        debug!(
            "Host account UID ({}) equals '{}' account's UID ({}). Not modifying '{}' account.",
            host_uid, config.app_account, app_account_details.uid, config.app_account,
        );
    } else {
        debug!(
            "Intending to change '{}' account's UID/GID from {}:{} to {}:{}.",
            config.app_account,
            app_account_details.uid,
            app_account_details.gid,
            host_uid,
            host_gid
        );
        ensure_no_account_already_using_host_uid(&config, host_uid);
        ensure_app_account_has_host_uid_and_gid(&config, &app_account_details, host_uid, host_gid);
        using_app_account = true;
    }

    if host_gid.as_raw() == 0 {
        debug!(
            "Host account GID ({}) is the root group. Not modifying '{}' group.",
            host_gid, app_account_details.group_name,
        );
    } else if host_gid == app_account_details.gid {
        debug!(
            "Host account GID ({}) equals '{}' account's GID ({}). Not modifying '{}' group.",
            host_gid, config.app_account, app_account_details.gid, app_account_details.group_name
        );
    } else {
        debug!(
            "Intending to change '{}' group's GID from {} to {}.",
            app_account_details.group_name, app_account_details.gid, host_gid
        );
        ensure_no_group_already_using_host_gid(&config, host_gid);
        ensure_app_group_has_host_gid(&config, &app_account_details, host_gid);
    }

    // The information in here is now stale, so make sure
    // we can't use it anymore.
    std::mem::drop(app_account_details);

    let target_account_details =
        lookup_target_account_details_or_abort(&config, host_uid, host_gid, using_app_account);
    maybe_chown_target_account_home_dir(&config, &target_account_details);
    run_hooks(&config, &target_account_details);
    change_user(&target_account_details);

    restore_old_path(old_path);
    maybe_execute_next_command(&target_account_details);
}
