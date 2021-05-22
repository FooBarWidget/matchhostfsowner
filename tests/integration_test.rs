mod common;

use common::*;
use std::error;

// /// Panics if the first expression is not strictly less than the second.
// /// Requires that the values be comparable with `<`.
// ///
// /// On failure, panics and prints the values out in a manner similar to
// /// prelude's `assert_eq!`.
// ///
// /// Optionally may take an additional message to display on failure, which
// /// is formatted using standard format syntax.
// ///
// /// # Example
// ///
// /// ```rust
// /// #[macro_use]
// /// extern crate more_asserts;
// ///
// /// fn main() {
// ///     assert_lt!(3, 4);
// ///     assert_lt!(3, 4, "With a message");
// ///     assert_lt!(3, 4, "With a formatted message: {}", "oh no");
// /// }
// /// ```
// #[macro_export]
// macro_rules! assert_lt {
//     ($left:expr, $right:expr) => ({
//         let (left, right) = (&($left), &($right));
//         if !(left < right) {
//             panic!("assertion failed: `(left < right)`\n  left: `{:?}`,\n right: `{:?}`",
//                    left, right);
//         }
//     });
//     ($left:expr, $right:expr, ) => ({
//         assert_lt!($left, $right);
//     });
//     ($left:expr, $right:expr, $($msg_args:tt)+) => ({
//         let (left, right) = (&($left), &($right));
//         if !(left < right) {
//             panic!("assertion failed: `(left < right)`\n  left: `{:?}`,\n right: `{:?}`: {}",
//                    left, right, format_args!($($msg_args)+));
//         }
//     })
// }

#[test]
fn test_running_allowed_when_having_normal_root_privileges() -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN addgroup --gid 1234 app",
        "RUN adduser --uid 1234 --gid 1234 --gecos '' --disabled-password app",
    ])?;
    let output = run_container(&image, &[], &[])?;
    assert!(output
        .text
        .find("Current process's privileges: uid=0 gid=0 euid=0 egid=0")
        .is_some());
    assert_eq!(Some(0), output.status.code());
    Ok(())
}

#[test]
fn test_running_allowed_when_having_normal_and_setuid_root_privileges(
) -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN chmod u+s,g+s /sbin/matchhostfsowner",
        "RUN addgroup --gid 1234 app",
        "RUN adduser --uid 1234 --gid 1234 --gecos '' --disabled-password app",
    ])?;
    let output = run_container(&image, &[], &[])?;
    assert!(output
        .text
        .find("Current process's privileges: uid=0 gid=0 euid=0 egid=0")
        .is_some());
    assert_eq!(Some(0), output.status.code());
    Ok(())
}

#[test]
fn test_running_allowed_when_setuid_root_and_pid1() -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN chmod u+s,g+s /sbin/matchhostfsowner",
        "RUN addgroup --gid 1234 app",
        "RUN adduser --uid 1234 --gid 1234 --gecos '' --disabled-password app",
    ])?;
    let output = run_container(&image, &["--user", "1234:1234"], &[])?;
    assert!(output
        .text
        .find("Current process's privileges: uid=1234 gid=1234 euid=0 egid=0")
        .is_some());
    assert_eq!(Some(0), output.status.code());
    Ok(())
}

#[test]
fn test_running_allowed_when_setuid_root_and_child_of_docker_init(
) -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN chmod u+s,g+s /sbin/matchhostfsowner",
        "RUN addgroup --gid 1234 app",
        "RUN adduser --uid 1234 --gid 1234 --gecos '' --disabled-password app",
    ])?;
    let output = run_container(&image, &["--init", "--user", "1234:1234"], &[])?;
    assert!(output
        .text
        .find("Current process's privileges: uid=1234 gid=1234 euid=0 egid=0")
        .is_some());
    assert_eq!(Some(0), output.status.code());
    Ok(())
}

#[test]
fn test_running_not_allowed_when_setuid_root_and_not_pid1_and_not_child_of_docker_init(
) -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN chmod u+s,g+s /sbin/matchhostfsowner",
        "RUN addgroup --gid 1234 app",
        "RUN adduser --uid 1234 --gid 1234 --gecos '' --disabled-password app",
    ])?;
    let output = run_container(
        &image,
        &["--user", "1234:1234", "--entrypoint", "sh"],
        &["-c", "matchhostfsowner"],
    )?;
    assert!(output
        .text
        .find("Matchhostfsowner may only be run when one of the following conditions apply")
        .is_some());
    assert!(output.status.code().is_some());
    assert_ne!(0, output.status.code().unwrap());
    Ok(())
}

#[test]
fn test_running_not_allowed_when_no_root_privileges() -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN addgroup --gid 1234 app",
        "RUN adduser --uid 1234 --gid 1234 --gecos '' --disabled-password app",
    ])?;
    let output = run_container(&image, &["--user", "1234:1234"], &[])?;
    assert!(output
        .text
        .find("Matchhostfsowner requires root privileges to operate")
        .is_some());
    assert!(output.status.code().is_some());
    assert_ne!(0, output.status.code().unwrap());
    Ok(())
}

#[test]
fn test_drop_setuid_bit_on_own_exe() -> Result<(), Box<dyn error::Error>> {
    let image = build_image(&[
        "RUN chmod u+s,g+s /sbin/matchhostfsowner",
        "RUN addgroup --gid 1234 app",
        "RUN adduser --uid 1234 --gid 1234 --gecos '' --disabled-password app",
    ])?;
    let output = run_container(
        &image,
        &["--user", "1234:1234"],
        &["stat", "/sbin/matchhostfsowner"],
    )?;
    assert!(output
        .text
        .find("Dropping setuid bit on /sbin/matchhostfsowner")
        .is_some());
    assert!(output.text.find("Access: (0755/-rwxr-xr-x)").is_some());
    assert_eq!(Some(0), output.status.code());
    Ok(())
}
