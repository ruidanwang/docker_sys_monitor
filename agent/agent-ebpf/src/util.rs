//! Provides some common functions
use aya_ebpf::helpers::bpf_probe_read_kernel_buf;//安全地从内核空间读取数据到用户空间

use agent_common::event::process::ProcInfo;//进程的各种属性（如 pid、tid、文件名等）

/*
作用
    copy_proc 函数用于将一个进程信息结构体的数据从 src 复制到 dst。
    主要用于在 eBPF 事件采集过程中，把内核态捕获的进程信息安全地拷贝到 ring buffer（环形缓冲区），以便用户空间读取和分析。
参数
    src: &ProcInfo：源进程信息，通常是从内核中读取的数据。
    dst: &mut ProcInfo：目标进程信息，通常是准备写入 ring buffer 的地方。
实现细节
1 基础字段赋值
    直接用赋值和 clone 把基础类型和结构体字段拷贝过去（pid, tid, ppid, creds, auid, cgroup）。
    clone 用于深拷贝结构体成员，防止共享引用导致内存安全问题。
    
2 敏感字符串字段的安全拷贝
    进程信息里的 filename、args、binary_path 是字符串或者字节数组（通常存储在内核空间）。
    用 bpf_probe_read_kernel_buf 从内核空间安全读取数据到目标字段。
    这些操作必须在 unsafe 块里进行，因为直接操作指针和内存，eBPF 要求开发者保证安全性。

3 返回值处理
    用 let _ = ... 表示忽略返回值，只关心数据拷贝，出错不会影响主流程（但实际开发时可以增加错误处理）。
*/
#[inline(always)]
pub fn copy_proc(src: &ProcInfo, dst: &mut ProcInfo) {
    dst.pid = src.pid;
    dst.tid = src.tid;
    dst.ppid = src.ppid;
    dst.creds = src.creds.clone();
    dst.auid = src.auid;
    dst.cgroup = src.cgroup.clone();
    unsafe {
        let _ = bpf_probe_read_kernel_buf(src.filename.as_ptr(), &mut dst.filename);
        let _ = bpf_probe_read_kernel_buf(src.args.as_ptr(), &mut dst.args);
        let _ = bpf_probe_read_kernel_buf(src.binary_path.as_ptr(), &mut dst.binary_path);
    }
}