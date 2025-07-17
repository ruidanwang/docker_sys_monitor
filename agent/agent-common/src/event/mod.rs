pub mod file;
pub mod process;

pub struct GenericEvent {
    pub ktime:u64,
    pub event:Event,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
#[repr(u8)]
pub enum Event {
    /// 0 - 31 reserved for common events
    ProcessExec(process::ProcInfo) = 0,
    ProcessExit(process::ProcInfo) = 1,
    File(file::FileMsg) = 2,
}

// Event message codes

/// ProcessExec message code
pub const MSG_PROCEXEC: u8 = 0;
/// ProcessExit message code
pub const MSG_PROCEXIT: u8 = 1;
/// File message code
pub const MSG_FILE: u8 = 2;
