#![no_std]
#![no_main]
//实现了文件操作的 eBPF 探针，包括文件打开、删除、修改权限、截断、挂载、mmap、ioctl 等事件。这些钩子（hook）通过 Linux 安全模块（LSM）接口捕获事件。
use aya_ebpf::{
    helpers::{
        bpf_d_path, bpf_get_current_pid_tgid, bpf_probe_read_kernel,
        bpf_probe_read_kernel_str_bytes,
    },
    macros::{lsm, map},
    maps::{array::Array, hash_map::HashMap, lpm_trie::LpmTrie},
    programs::LsmContext,
};

use agent_common::config::filemon::Config;

use agent_common::constants::{MAX_FILENAME_SIZE, MAX_FILE_PATH, MAX_FILE_PREFIX};
use agent_common::event::file::{
    HOOK_FILE_IOCTL, HOOK_FILE_OPEN, HOOK_MMAP_FILE, HOOK_PATH_CHMOD, HOOK_PATH_CHOWN,
    HOOK_PATH_TRUNCATE, HOOK_PATH_UNLINK, HOOK_SB_MOUNT,
};
use agent_common::event::process::ProcInfo;
use agent_common::event::{Event, MSG_FILE};
use agent_common::vmlinux::{dentry, file, fmode_t, kgid_t, kuid_t, path, qstr};

use agent_ebpf::{
    event_capture, event_map::rb_event_init, filter::process::ProcessFilter, util,
};
//多个 eBPF Map 用于在内核和用户空间间或不同探针间共享数据，如配置信息、进程信息、过滤条件等。
//存储进程信息
#[map]
static PROCMON_PROC_MAP: HashMap<u32, ProcInfo> = HashMap::pinned(1, 0);
//配置信息
#[map]
static FILEMON_CONFIG: Array<Config> = Array::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_UID_MAP: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_EUID_MAP: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_AUID_MAP: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_BINPATH_MAP: HashMap<[u8; MAX_FILE_PATH], u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_BINNAME_MAP: HashMap<[u8; MAX_FILENAME_SIZE], u8> =
    HashMap::with_max_entries(1, 0);

#[map]
static FILEMON_FILTER_BINPREFIX_MAP: LpmTrie<[u8; MAX_FILE_PREFIX], u8> =
    LpmTrie::with_max_entries(1, 0);

const FMODE_EXEC: u32 = 1 << 5;

//捕获文件打开事件，过滤掉作为执行（EXEC）方式打开的文件。
#[lsm(hook = "file_open")]
pub fn file_open_capture(ctx: LsmContext) -> i32 {
    event_capture!(ctx, MSG_FILE, false, try_open)
}

fn try_open(ctx: LsmContext, event: &mut Event) -> Result<i32, i32> {
    //1.获取配置和进程信息：通过 map 读取。
    let Some(config_ptr) = FILEMON_CONFIG.get_ptr(0) else {
        return Err(0);
    };
    let config = unsafe { config_ptr.as_ref() };
    let Some(config) = config else {
        return Err(0);
    };
    let Event::File(event) = event else {
        return Err(0);
    };

    //2 过滤：根据配置的过滤条件，用 ProcessFilter 进行进程属性（uid/euid/auid/路径等）过滤。
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let proc = unsafe { PROCMON_PROC_MAP.get(&pid) };
    let Some(proc) = proc else {
        return Err(0);
    };

    // Filter event by process
    let allow = if !config.filter_mask.is_empty() {
        let process_filter: ProcessFilter = ProcessFilter::new(
            &FILEMON_FILTER_UID_MAP,
            &FILEMON_FILTER_EUID_MAP,
            &FILEMON_FILTER_AUID_MAP,
            &FILEMON_FILTER_BINNAME_MAP,
            &FILEMON_FILTER_BINPATH_MAP,
            &FILEMON_FILTER_BINPREFIX_MAP,
        );
        if config.deny_list {
            !process_filter.filter(config.filter_mask, proc)
        } else {
            process_filter.filter(config.filter_mask, proc)
        }
    } else {
        true
    };

    // Skip argument parsing if event is not exported
    if !allow {
        return Err(0);
    }
    //3 处理感兴趣的事件：只有通过过滤的事件才会被进一步采集和填充细节（如文件路径、权限、用户、组等）。
    event.hook = HOOK_FILE_OPEN;
    unsafe {
        let fp: *const file = ctx.arg(0);
        let fmode: fmode_t = (*fp).f_mode;
        // Do not check opened files for execution. We have procmon for this
        if fmode & FMODE_EXEC != 0 {
            return Err(0);
        }
        //4.数据采集：用 bpf helper 函数（如 bpf_d_path、bpf_probe_read_kernel）获取内核数据结构内容，转换为事件信息。
        let _ = bpf_d_path(
            &(*fp).f_path as *const _ as *mut aya_ebpf::bindings::path,
            event.path.as_mut_ptr() as *mut _,
            event.path.len() as u32,
        );
        event.flags = (*fp).f_flags;
        event.i_mode = (*(*fp).f_inode).i_mode;
        event.uid = bpf_probe_read_kernel::<kuid_t>(&(*(*fp).f_inode).i_uid as *const _)
            .map_err(|_| 0i32)?
            .val;
        event.gid = bpf_probe_read_kernel::<kgid_t>(&(*(*fp).f_inode).i_gid as *const _)
            .map_err(|_| 0i32)?
            .val;
    }
    util::copy_proc(proc, &mut event.process);
    Ok(0)
}