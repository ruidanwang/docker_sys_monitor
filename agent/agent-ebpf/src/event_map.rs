/*
    核心目的是为 eBPF 事件检测提供统一的事件发送和处理机制。
    通过 ring buffer 在内核和用户空间之间高效传递事件，支持事件的初始化、填充及提交/丢弃。
    event_capture 宏简化了事件处理流程，提升代码复用。
*/

//! 所有检测器之间事件的 ring buffer。
use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::map,
    maps::{ring_buf::RingBufEntry, RingBuf},
};

use agent_common::event::{Event, GenericEvent};
//声明一个全局静态的 ring buffer 映射 EVENT_MAP，用于跨 eBPF 组件传递事件。
//RingBuf::pinned(1, 0) 定义了缓冲区的参数。
#[map]
pub static EVENT_MAP: RingBuf = RingBuf::pinned(1, 0);

#[inline(always)]
/**
功能：为给定类型的事件预留 ring buffer 空间，并可选择性地初始化为零。
参数：
    msg_code：事件类型编码。
    zero：是否将缓冲区填充为零。
实现：
    调用 EVENT_MAP.reserve 预留空间。
    如果 zero 为 true，使用 memset 将空间清零。
    设置事件类型（msg_code）。
    记录事件发生时间（ktime）。
    返回预留的事件条目。
**/
pub fn rb_event_init(msg_code: u8, zero: bool) -> Result<RingBufEntry<GenericEvent>, i32> {
    let Some(mut event_rb) = EVENT_MAP.reserve::<GenericEvent>(0) else {
        return Err(0);
    };
    unsafe {
        if zero {
            aya_ebpf::memset(
                event_rb.as_mut_ptr() as *mut u8,
                0,
                core::mem::size_of_val(&event_rb),
            );
        }
        let event_ref = &mut *event_rb.as_mut_ptr();
        let p = &mut event_ref.event as *mut Event as *mut u8;
        *p = msg_code;
        event_ref.ktime = bpf_ktime_get_ns();
    }
    Ok(event_rb)
}

/**
用于自动化捕获和处理事件，简化 eBPF 钩子的事件分发流程。
参数：
    ctx：钩子的执行上下文（例如 kprobe、tracepoint 等）。
    msg_code：事件类型编码。
    zero：是否初始化为零。
    handler：事件处理函数。
流程：
    1 调用 rb_event_init 初始化事件。
    2 调用 handler 处理事件内容。
    3 如果处理成功，提交事件；否则丢弃事件。
**/
#[macro_export]
macro_rules! event_capture {
    ($ctx:expr, $msg_code:expr, $zero:expr, $handler:expr) => {{
        let Ok(mut event_rb) = rb_event_init($msg_code, $zero) else {
            return 0;
        };
        let event_ref = unsafe { &mut *event_rb.as_mut_ptr() };
        match $handler($ctx, &mut event_ref.event) {
            Ok(ret) => {
                event_rb.submit(0);
                ret
            }
            Err(ret) => {
                event_rb.discard(0);
                ret
            }
        }
    }};
}