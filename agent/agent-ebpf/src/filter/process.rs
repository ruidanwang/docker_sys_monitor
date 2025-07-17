/*
2025-07-18
检测器模块的进程过滤器实现。在内核中判断某个进程信息（ProcInfo）是否通过一组白名单过滤条件

*/

use aya_ebpf::{
    helpers::bpf_probe_read_kernel_buf,
    macros::map,
    maps::{
        hash_map::HashMap,
        lpm_trie::{Key, LpmTrie},
        per_cpu_array::PerCpuArray,
    },
};
use agent_common::constants::{MAX_FILENAME_SIZE, MAX_FILE_PATH, MAX_FILE_PREFIX};

use agent_common::config::procmon::ProcessFilterMask;//需要过滤哪些进程属性的掩码
use agent_common::event::process::ProcInfo;//进程信息结构体
//全局静态map
//用于临时存储二进制路径前缀，供 LPM（最长前缀匹配）trie 过滤用。
//使用 PerCpuArray 保证在多核环境下每个 CPU 有独立空间，避免并发冲突。
#[map]
static FILTER_BIN_PREFIX_MAP: PerCpuArray<Key<[u8; MAX_FILE_PREFIX]>> =
    PerCpuArray::with_max_entries(1, 0);

/*
保存一组 map 的引用，每个 map 代表一种允许通过的白名单条件：
    用户 ID、有效用户 ID、审计用户 ID
    二进制文件名、完整路径、路径前缀（LPM Trie）
*/
pub struct ProcessFilter<'a> {
    uid_map: &'a HashMap<u32, u8>,
    euid_map: &'a HashMap<u32, u8>,
    auid_map: &'a HashMap<u32, u8>,
    binary_name_map: &'a HashMap<[u8; MAX_FILENAME_SIZE], u8>,
    binary_path_map: &'a HashMap<[u8; MAX_FILE_PATH], u8>,
    binary_prefix_map: &'a LpmTrie<[u8; MAX_FILE_PREFIX], u8>,
}

impl<'a> ProcessFilter<'a> {
    //初始化 ProcessFilter，将各种 map（白名单）传进来，方便后续调用。
    pub fn new(
        uid_map: &'a HashMap<u32, u8>,
        euid_map: &'a HashMap<u32, u8>,
        auid_map: &'a HashMap<u32, u8>,
        binary_name_map: &'a HashMap<[u8; MAX_FILENAME_SIZE], u8>,
        binary_path_map: &'a HashMap<[u8; MAX_FILE_PATH], u8>,
        binary_prefix_map: &'a LpmTrie<[u8; MAX_FILE_PREFIX], u8>,
    ) -> Self {
        ProcessFilter {
            uid_map,
            euid_map,
            auid_map,
            binary_name_map,
            binary_path_map,
            binary_prefix_map,
        }
    }

    /*
    判断某个进程（proc）是否符合过滤规则（mask 指定要比对哪些项）。
        只有所有启用的 UID/EUID/AUID 过滤项通过，且至少有一个二进制过滤项匹配时，才判定通过。
        该方法同时支持白名单和黑名单场景。
    */
    pub fn filter(&self, mask: ProcessFilterMask, proc: &ProcInfo) -> bool {
        //1 先按 mask 检查 UID/EUID/AUID 白名单：
        //      只要有一个没通过（map 查不到 key），直接返回 false。
        if mask.contains(ProcessFilterMask::UID) && self.uid_map.get_ptr(&proc.creds.uid).is_none()
        {
            return false;
        }
        if mask.contains(ProcessFilterMask::EUID)
            && self.euid_map.get_ptr(&proc.creds.euid).is_none()
        {
            return false;
        }
        if mask.contains(ProcessFilterMask::AUID) && self.auid_map.get_ptr(&proc.auid).is_none() {
            return false;
        }
        //2 判断二进制（可执行文件）相关过滤是否被启用（名字、路径、路径前缀）：
        //      如果没有这些过滤项，说明只需要基于 UID/EUID/AUID 过滤，直接返回 true。
        if mask
            .intersection(
                ProcessFilterMask::BINARY_NAME
                    | ProcessFilterMask::BINARY_PATH
                    | ProcessFilterMask::BINARY_PATH_PREFIX,
            )
            .is_empty()
        {
            return true;
        }
        //3 针对每个二进制过滤项：
        //      BINARY_NAME：二进制文件名在白名单中，返回 true。
        if mask.contains(ProcessFilterMask::BINARY_NAME)
            && self.binary_name_map.get_ptr(&proc.filename).is_some()
        {
            return true;
        }
        //      BINARY_PATH：二进制完整路径在白名单中，返回 true。
        if mask.contains(ProcessFilterMask::BINARY_PATH)
            && self.binary_path_map.get_ptr(&proc.binary_path).is_some()
        {
            return true;
        }
        //      BINARY_PATH_PREFIX：用 LPM Trie 判断二进制路径的最长前缀是否在白名单中。如果是，返回 true。
        if mask.contains(ProcessFilterMask::BINARY_PATH_PREFIX) {
            let Some(prefix) = FILTER_BIN_PREFIX_MAP.get_ptr_mut(0) else {
                return false;
            };
            let prefix = unsafe { prefix.as_mut() };
            let Some(prefix) = prefix else {
                return false;
            };
            let _ = unsafe {
                //安全地将进程的二进制路径（proc.binary_path）拷贝到 prefix.data 这个缓冲区，并在拷贝前先把该缓冲区清零
                aya_ebpf::memset(
                    prefix.data.as_mut_ptr(),
                    0,
                    core::mem::size_of_val(&prefix.data),
                );
                bpf_probe_read_kernel_buf(&proc.binary_path as *const _, &mut prefix.data)
            };
            //这里使用 FILTER_BIN_PREFIX_MAP 作为缓冲，将 proc.binary_path 拷贝到 prefix，设置好 prefix_len，然后查询 trie。
            prefix.prefix_len = (MAX_FILE_PREFIX * 8) as u32;
            if self.binary_prefix_map.get(prefix).is_some() {
                return true;
            }
        }
        //4 如果都没匹配成功，返回 false。
        false
    }
}