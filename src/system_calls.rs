///! This module wraps system calls. Wrapped system calls are defined in the
///! [SystemCalls] trait. RealSystemCalls provides a real implementation.
///! During tests, you can provide your own mock implementations so that no
///! actual system calls are made.
use nix::unistd::{Gid, Group, Uid, User};

pub trait SystemCalls {
    fn lookup_user_by_uid(self: &mut Self, uid: Uid) -> nix::Result<Option<User>> {
        User::from_uid(uid)
    }

    fn lookup_group_by_gid(self: &mut Self, gid: Gid) -> nix::Result<Option<Group>> {
        Group::from_gid(gid)
    }
}

pub struct RealSystemCalls {}

impl SystemCalls for RealSystemCalls {}
