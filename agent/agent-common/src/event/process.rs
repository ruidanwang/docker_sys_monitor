//! Process event module

use bitflags::bitflags;

#[cfg(feature = "user")]
use serde::Serialize;

#[cfg(feature = "user")]
use serde::ser::Serializer;

use crate::constants::{DOCKER_ID_LENGTH, MAX_ARGS_SIZE, MAX_FILENAME_SIZE, MAX_FILE_PATH};

/// Process event
#[derive(Clone, Debug)]
#[repr(C)]
pub struct ProcInfo {
    /// PID
    pub pid: u32,
    /// TID
    pub tid: u32,
    /// Parent PID
    pub ppid: u32,
    /// Task Creds
    pub creds: Cred,
    /// login UID
    pub auid: u32,
    /// if this event from clone
    pub clonned: bool,
    /// executable name
    pub filename: [u8; MAX_FILENAME_SIZE],
    /// full binary path
    pub binary_path: [u8; MAX_FILE_PATH],
    /// command line arguments without argv[0]
    pub args: [u8; MAX_ARGS_SIZE],
    /// Cgroup info
    pub cgroup: Cgroup,
}

/// Creds
#[derive(Clone, Debug)]
#[repr(C)]
pub struct Cred {
    /// UID
    pub uid: u32,
    /// EUID
    pub euid: u32,
    pub cap_inheritable: u64,
    pub cap_permitted: u64,
    pub cap_effective: u64,
    pub secureexec: SecureExec,
}

/// Cgroup info
#[derive(Clone, Debug)]
#[repr(C)]
pub struct Cgroup {
    pub cgroup_id: u64,
    pub cgroup_name: [u8; DOCKER_ID_LENGTH],
}

bitflags! {
    #[derive(Clone, Debug, PartialEq)]
    // #[cfg_attr(feature = "user", derive(Serialize))]
    #[repr(C)]
    pub struct SecureExec: u32 {
        const SETUID = 0b00000001;
        const SETGID = 0b00000010;
        const FILE_CAPS = 0b00000100;
    }
}

#[cfg(feature = "user")]
impl Serialize for SecureExec {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // 你选择的序列化方式，比如 bits() 或字符串数组
        serializer.serialize_u32(self.bits())
    }
}


// #[cfg(feature = "user")]
// impl Serialize for SecureExec {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         // 你选择的序列化方式，比如 bits() 或字符串数组
//         serializer.serialize_u32(self.bits())
//     }
// }