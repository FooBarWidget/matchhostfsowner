mod common;

use common::*;
use regex::{Match, Regex};
use std::error;

#[test]
fn test_running_allowed_when_having_normal_root_privileges() -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN groupadd --gid 1234 app",
        "RUN useradd -m --uid 1234 --gid 1234 --comment '' app",
    ])?;
    let output = run_container(&image, &[], &[])?;
    assert_contains_substr!(
        output.text,
        "Current process's privileges: uid=0 gid=0 euid=0 egid=0"
    );
    assert_eq!(Some(0), output.status.code);
    Ok(())
}

#[test]
fn test_running_allowed_when_having_normal_and_setuid_root_privileges()
-> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN chmod u+s,g+s /sbin/matchhostfsowner",
        "RUN groupadd --gid 1234 app",
        "RUN useradd -m --uid 1234 --gid 1234 --comment '' app",
    ])?;
    let output = run_container(&image, &[], &[])?;
    assert_contains_substr!(
        output.text,
        "Current process's privileges: uid=0 gid=0 euid=0 egid=0"
    );
    assert_eq!(Some(0), output.status.code);
    Ok(())
}

#[test]
fn test_running_allowed_when_setuid_root_and_pid1() -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN chmod u+s,g+s /sbin/matchhostfsowner",
        "RUN groupadd --gid 1234 app",
        "RUN useradd -m --uid 1234 --gid 1234 --comment '' app",
    ])?;
    let output = run_container(&image, &["--user", "1234:1234"], &[])?;
    assert_contains_substr!(
        output.text,
        "Current process's privileges: uid=1234 gid=1234 euid=0 egid=0"
    );
    assert_eq!(Some(0), output.status.code);
    Ok(())
}

#[test]
fn test_running_allowed_when_setuid_root_and_child_of_docker_init()
-> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN chmod u+s,g+s /sbin/matchhostfsowner",
        "RUN groupadd --gid 1234 app",
        "RUN useradd -m --uid 1234 --gid 1234 --comment '' app",
    ])?;
    let output = run_container(&image, &["--init", "--user", "1234:1234"], &[])?;
    assert_contains_substr!(
        output.text,
        "Current process's privileges: uid=1234 gid=1234 euid=0 egid=0"
    );
    assert_eq!(Some(0), output.status.code);
    Ok(())
}

#[test]
fn test_running_not_allowed_when_setuid_root_and_not_pid1_and_not_child_of_docker_init()
-> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN chmod u+s,g+s /sbin/matchhostfsowner",
        "RUN groupadd --gid 1234 app",
        "RUN useradd -m --uid 1234 --gid 1234 --comment '' app",
    ])?;
    let output = run_container(
        &image,
        &["--user", "1234:1234", "--entrypoint", "sh"],
        &["-c", "matchhostfsowner"],
    )?;
    assert_contains_substr!(
        output.text,
        "Matchhostfsowner may only be run when one of the following conditions apply"
    );
    assert!(output.status.code.is_some());
    assert_ne!(0, output.status.code.unwrap());
    Ok(())
}

#[test]
fn test_running_not_allowed_when_no_root_privileges() -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN groupadd --gid 1234 app",
        "RUN useradd -m --uid 1234 --gid 1234 --comment '' app",
    ])?;
    let output = run_container(&image, &["--user", "1234:1234"], &[])?;
    assert_contains_substr!(
        output.text,
        "Matchhostfsowner requires root privileges to operate"
    );
    assert!(output.status.code.is_some());
    assert_ne!(0, output.status.code.unwrap());
    Ok(())
}

#[test]
fn test_drop_setuid_bit_on_own_exe() -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN chmod u+s,g+s /sbin/matchhostfsowner",
        "RUN groupadd --gid 1234 app",
        "RUN useradd -m --uid 1234 --gid 1234 --comment '' app",
    ])?;
    let output = run_container(
        &image,
        &["--user", "1234:1234"],
        &["stat", "/sbin/matchhostfsowner"],
    )?;
    assert_contains_substr!(
        output.text,
        "Dropping setuid bit on /usr/sbin/matchhostfsowner"
    );
    assert!(output.text.find("Access: (0755/-rwxr-xr-x)").is_some());
    assert_eq!(Some(0), output.status.code);
    Ok(())
}

#[test]
fn test_match_user_non_root() -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN groupadd --gid 1234 app",
        "RUN useradd -m --uid 1234 --gid 1234 --comment '' app",
    ])?;
    let output = run_container(
        &image,
        &["-e", "MHF_HOST_UID=1300", "-e", "MHF_HOST_GID=1301"],
        &["id"],
    )?;
    assert_contains_substr!(
        output.text,
        "uid=1300(app) gid=1301(app) groups=1301(app)\n"
    );
    assert_eq!(Some(0), output.status.code);
    Ok(())
}

#[test]
fn test_match_user_root_user() -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN groupadd --gid 1234 app",
        "RUN useradd -m --uid 1234 --gid 1234 --comment '' app",
    ])?;
    let output = run_container(
        &image,
        &["-e", "MHF_HOST_UID=0", "-e", "MHF_HOST_GID=1301"],
        &["id"],
    )?;
    assert_contains_substr!(output.text, "Account to switch to is 'root'");
    assert_contains_substr!(output.text, "Group to switch to is 'app'");
    assert_contains_substr!(output.text, "uid=0(root) gid=1301(app) groups=1301(app)\n");
    assert_eq!(Some(0), output.status.code);
    Ok(())
}

#[test]
fn test_match_user_root_group() -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN groupadd --gid 1234 app",
        "RUN useradd -m --uid 1234 --gid 1234 --comment '' app",
    ])?;
    let output = run_container(
        &image,
        &["-e", "MHF_HOST_UID=1300", "-e", "MHF_HOST_GID=0"],
        &["id"],
    )?;
    assert_contains_substr!(output.text, "Account to switch to is 'app'");
    assert_contains_substr!(output.text, "Group to switch to is 'root'");
    assert_contains_substr!(output.text, "uid=1300(app) gid=0(root) groups=0(root)\n");
    assert_eq!(Some(0), output.status.code);
    Ok(())
}

#[test]
fn test_host_uid_given_host_gid_not_given() -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN groupadd --gid 1234 app",
        "RUN useradd -m --uid 1234 --gid 1234 --comment '' app",
    ])?;
    let output = run_container(&image, &["-e", "MHF_HOST_UID=1300"], &["id"])?;
    assert_contains_substr!(
        output.text,
        "MHF_HOST_UID (set to '1300') and MHF_HOST_GID (set to '<no value>') \
         must both be given, or neither must be given"
    );
    assert!(!output.status.success());
    Ok(())
}

#[test]
fn test_host_uid_not_given_host_gid_given() -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN groupadd --gid 1234 app",
        "RUN useradd -m --uid 1234 --gid 1234 --comment '' app",
    ])?;
    let output = run_container(&image, &["-e", "MHF_HOST_GID=1300"], &["id"])?;
    assert_contains_substr!(
        output.text,
        "MHF_HOST_UID (set to '<no value>') and MHF_HOST_GID (set to '1300') \
         must both be given, or neither must be given"
    );
    assert!(!output.status.success());
    Ok(())
}

#[test]
fn test_match_user_conflicting_user() -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN groupadd --gid 1234 app",
        "RUN useradd -m --uid 1234 --gid 1234 --comment '' app",
    ])?;
    let output = run_container(
        &image,
        &["-e", "MHF_HOST_UID=1", "-e", "MHF_HOST_GID=1301"],
        &["id"],
    )?;
    assert_contains_substr!(
        output.text,
        "Host UID (1) already occupied by account 'daemon'. Will change that account's UID.\n"
    );
    assert_contains_substr!(output.text, "uid=1(app) gid=1301(app) groups=1301(app)\n");
    assert_eq!(Some(0), output.status.code);
    Ok(())
}

#[test]
fn test_match_user_conflicting_group() -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN groupadd --gid 1234 app",
        "RUN useradd -m --uid 1234 --gid 1234 --comment '' app",
    ])?;
    let output = run_container(
        &image,
        &["-e", "MHF_HOST_UID=1300", "-e", "MHF_HOST_GID=1"],
        &["id"],
    )?;
    assert_contains_substr!(
        output.text,
        "Host GID (1) already occupied by group 'daemon'. Will change that group's GID.\n"
    );
    assert_contains_substr!(output.text, "uid=1300(app) gid=1(app) groups=1(app)\n");
    assert_eq!(Some(0), output.status.code);
    Ok(())
}

// https://github.com/FooBarWidget/matchhostfsowner/issues/11
#[test]
fn test_match_app_account_primary_gid_when_mitigating_conflicting_group()
-> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN groupadd --gid 1234 app",
        "RUN useradd -m --uid 1234 --gid 1234 --comment '' app",
    ])?;
    let output = run_container(
        &image,
        &["-e", "MHF_HOST_UID=1300", "-e", "MHF_HOST_GID=1"],
        &["id", "app"],
    )?;
    assert_contains_substr!(
        output.text,
        "Account to switch to is 'app' (UID/GID = 1300:1,"
    );
    assert_contains_substr!(output.text, "uid=1300(app) gid=1(app) groups=1(app)\n");
    assert_eq!(Some(0), output.status.code);
    Ok(())
}

#[test]
fn test_match_user_via_docker_cli_user_arg() -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN chmod u+s,g+s /sbin/matchhostfsowner",
        "RUN groupadd --gid 1234 app",
        "RUN useradd -m --uid 1234 --gid 1234 --comment '' app",
    ])?;
    let output = run_container(&image, &["--user", "1300:1301"], &["id"])?;
    assert_contains_substr!(
        output.text,
        "Current process's privileges: uid=1300 gid=1301 euid=0 egid=0"
    );
    assert_contains_substr!(
        output.text,
        "uid=1300(app) gid=1301(app) groups=1301(app)\n"
    );
    assert_eq!(Some(0), output.status.code);
    Ok(())
}

#[test]
fn test_match_user_preserves_supplementary_groups_when_account_and_group_names_differ()
-> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN groupadd --gid 41000 appgroup",
        "RUN groupadd --gid 42000 extra",
        "RUN useradd -m --uid 41001 --gid 41000 --groups extra --comment '' appuser",
    ])?;

    let output = run_container(
        &image,
        &[
            "-e",
            "MHF_HOST_UID=43000",
            "-e",
            "MHF_HOST_GID=43001",
            "-e",
            "MHF_APP_ACCOUNT=appuser",
            "-e",
            "MHF_APP_GROUP=appgroup",
        ],
        &["id"],
    )?;

    assert_contains_substr!(output.text, "uid=43000(appuser) gid=43001(appgroup)");
    assert_contains_substr!(output.text, "42000(extra)");
    assert_eq!(Some(0), output.status.code);
    Ok(())
}

#[test]
fn test_idempotent() -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN groupadd --gid 1234 app",
        "RUN useradd -m --uid 1234 --gid 1234 --comment '' app",
    ])?;
    let container = run_restartable_container(
        &image,
        &["-e", "MHF_HOST_UID=1300", "-e", "MHF_HOST_GID=1301"],
        &["id"],
    )
    .map_err(|e| GenericError(format!("Error starting container: {}", e)))?;

    let output = wait_container_and_capture_output(container.container_id.as_str())?;
    assert!(output.status.success());

    restart_container(container.container_id.as_str())?;
    let output = wait_container_and_capture_output(container.container_id.as_str())?;
    assert_contains_substr!(
        output.text,
        "uid=1300(app) gid=1301(app) groups=1301(app)\n"
    );
    assert!(output.status.success());

    Ok(())
}

#[test]
fn test_user_root_group_idempotent() -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN groupadd --gid 1234 app",
        "RUN useradd -m --uid 1234 --gid 1234 --comment '' app",
    ])?;
    let container = run_restartable_container(
        &image,
        &["-e", "MHF_HOST_UID=1300", "-e", "MHF_HOST_GID=0"],
        &["id"],
    )
    .map_err(|e| GenericError(format!("Error starting container: {}", e)))?;

    let output = wait_container_and_capture_output(container.container_id.as_str())?;
    assert!(output.status.success());

    restart_container(container.container_id.as_str())?;
    let output = wait_container_and_capture_output(container.container_id.as_str())?;
    println!(
        "----- Container output -----\n{}\n---------------------",
        output.text
    );

    let re = Regex::new(r"Executing command specified by CLI arguments: .*\n(.*?)\n")?;
    let matches: Vec<Match> = re.find_iter(&output.text).collect();
    assert_eq!(matches.len(), 2);
    assert_contains_substr!(
        matches[1].as_str(),
        "uid=1300(app) gid=0(root) groups=0(root)\n"
    );
    assert!(output.status.success());

    Ok(())
}

#[test]
fn test_config_file_with_secure_permissions_allowed() -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN groupadd --gid 1234 app",
        "RUN useradd -m --uid 1234 --gid 1234 --comment '' app",
        "RUN mkdir -p /etc/matchhostfsowner",
        "RUN printf '%s\\n' 'host_uid: 1300' 'host_gid: 1301' > /etc/matchhostfsowner/config.yml",
        "RUN chown root:root /etc/matchhostfsowner /etc/matchhostfsowner/config.yml",
        "RUN chmod 0700 /etc/matchhostfsowner",
        "RUN chmod 0600 /etc/matchhostfsowner/config.yml",
    ])?;

    let output = run_container(&image, &[], &["id"])?;
    assert_contains_substr!(output.text, "uid=1300(app) gid=1301(app)");
    assert!(output.status.success());

    Ok(())
}

#[test]
fn test_config_file_non_root_user_owned_rejected() -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN groupadd --gid 1234 app",
        "RUN useradd -m --uid 1234 --gid 1234 --comment '' app",
        "RUN mkdir -p /etc/matchhostfsowner",
        "RUN printf '%s\\n' 'host_uid: 1300' 'host_gid: 1301' > /etc/matchhostfsowner/config.yml",
        "RUN chown root:root /etc/matchhostfsowner",
        "RUN chown app:root /etc/matchhostfsowner/config.yml",
        "RUN chmod 0700 /etc/matchhostfsowner",
        "RUN chmod 0600 /etc/matchhostfsowner/config.yml",
    ])?;

    let output = run_container(&image, &[], &["id"])?;
    assert_contains_substr!(
        output.text,
        "Error loading /etc/matchhostfsowner/config.yml (security reason): must be owned by user root and group root"
    );
    assert!(!output.status.success());

    Ok(())
}

#[test]
fn test_config_file_non_root_group_owned_rejected() -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN groupadd --gid 1234 app",
        "RUN useradd -m --uid 1234 --gid 1234 --comment '' app",
        "RUN mkdir -p /etc/matchhostfsowner",
        "RUN printf '%s\\n' 'host_uid: 1300' 'host_gid: 1301' > /etc/matchhostfsowner/config.yml",
        "RUN chown root:root /etc/matchhostfsowner",
        "RUN chown root:app /etc/matchhostfsowner/config.yml",
        "RUN chmod 0700 /etc/matchhostfsowner",
        "RUN chmod 0600 /etc/matchhostfsowner/config.yml",
    ])?;

    let output = run_container(&image, &[], &["id"])?;
    assert_contains_substr!(
        output.text,
        "Error loading /etc/matchhostfsowner/config.yml (security reason): must be owned by user root and group root"
    );
    assert!(!output.status.success());

    Ok(())
}

#[test]
fn test_config_file_strict_permissions_required() -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN groupadd --gid 1234 app",
        "RUN useradd -m --uid 1234 --gid 1234 --comment '' app",
        "RUN mkdir -p /etc/matchhostfsowner",
        "RUN printf '%s\\n' 'host_uid: 1300' 'host_gid: 1301' > /etc/matchhostfsowner/config.yml",
        "RUN chown root:root /etc/matchhostfsowner",
        "RUN chown root:root /etc/matchhostfsowner/config.yml",
        "RUN chmod 0700 /etc/matchhostfsowner",
        "RUN chmod 0644 /etc/matchhostfsowner/config.yml",
    ])?;

    let output = run_container(&image, &[], &["id"])?;
    assert_contains_substr!(
        output.text,
        "Error loading /etc/matchhostfsowner/config.yml (security reason): must have permissions u=rw,g=,o= (mode 0600)"
    );
    assert!(!output.status.success());

    Ok(())
}

#[test]
fn test_config_file_non_root_writable_parents_rejected() -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN groupadd --gid 1234 app",
        "RUN useradd -m --uid 1234 --gid 1234 --comment '' app",
        "RUN mkdir -p /etc/matchhostfsowner",
        "RUN printf '%s\\n' 'host_uid: 1300' 'host_gid: 1301' > /etc/matchhostfsowner/config.yml",
        "RUN chown root:root /etc/matchhostfsowner /etc/matchhostfsowner/config.yml",
        "RUN chmod 0777 /etc/matchhostfsowner",
        "RUN chmod 0600 /etc/matchhostfsowner/config.yml",
    ])?;

    let output = run_container(&image, &[], &["id"])?;
    assert_contains_substr!(
        output.text,
        "Error loading /etc/matchhostfsowner/config.yml (security reason): parent directory /etc/matchhostfsowner must not be writable by anyone other than user root and group root"
    );
    assert!(!output.status.success());

    let image = build_image(&[
        "RUN groupadd --gid 1234 app",
        "RUN useradd -m --uid 1234 --gid 1234 --comment '' app",
        "RUN mkdir -p /etc/matchhostfsowner",
        "RUN printf '%s\\n' 'host_uid: 1300' 'host_gid: 1301' > /etc/matchhostfsowner/config.yml",
        "RUN chown root:root /etc/matchhostfsowner /etc/matchhostfsowner/config.yml",
        "RUN chmod 0755 /etc/matchhostfsowner",
        "RUN chmod 0600 /etc/matchhostfsowner/config.yml",
        "RUN chmod 0777 /etc",
    ])?;

    let output = run_container(&image, &[], &["id"])?;
    assert_contains_substr!(
        output.text,
        "Error loading /etc/matchhostfsowner/config.yml (security reason): parent directory /etc must not be writable by anyone other than user root and group root"
    );
    assert!(!output.status.success());

    Ok(())
}

#[test]
fn test_config_file_symlink_rejected() -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN groupadd --gid 1234 app",
        "RUN useradd -m --uid 1234 --gid 1234 --comment '' app",
        "RUN mkdir -p /etc/matchhostfsowner /etc/matchhostfsowner-real",
        "RUN printf '%s\\n' 'host_uid: 1300' 'host_gid: 1301' > /etc/matchhostfsowner-real/config.yml",
        "RUN chown root:root /etc/matchhostfsowner /etc/matchhostfsowner-real /etc/matchhostfsowner-real/config.yml",
        "RUN chmod 0700 /etc/matchhostfsowner /etc/matchhostfsowner-real",
        "RUN chmod 0600 /etc/matchhostfsowner-real/config.yml",
        "RUN ln -s /etc/matchhostfsowner-real/config.yml /etc/matchhostfsowner/config.yml",
    ])?;

    let output = run_container(&image, &[], &["id"])?;
    assert_contains_substr!(
        output.text,
        "Error loading /etc/matchhostfsowner/config.yml (security reason): it must not be a symlink"
    );
    assert!(!output.status.success());

    Ok(())
}

#[test]
fn test_config_file_parent_symlinks_rejected() -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN groupadd --gid 1234 app",
        "RUN useradd -m --uid 1234 --gid 1234 --comment '' app",
        "RUN mkdir -p /etc/matchhostfsowner-real",
        "RUN ln -s /etc/matchhostfsowner-real /etc/matchhostfsowner",
        "RUN printf '%s\\n' 'host_uid: 1300' 'host_gid: 1301' > /etc/matchhostfsowner/config.yml",
        "RUN chown root:root /etc/matchhostfsowner /etc/matchhostfsowner/config.yml",
        "RUN chmod 0700 /etc/matchhostfsowner",
        "RUN chmod 0600 /etc/matchhostfsowner/config.yml",
    ])?;

    let output = run_container(&image, &[], &["id"])?;
    assert_contains_substr!(
        output.text,
        "Error loading /etc/matchhostfsowner/config.yml (security reason): parent directory /etc/matchhostfsowner must not be a symlink"
    );
    assert!(!output.status.success());

    Ok(())
}
