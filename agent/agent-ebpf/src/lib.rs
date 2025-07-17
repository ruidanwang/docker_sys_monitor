#![no_std]
#![no_main]
pub mod util;
pub mod event_map;
// This file exists to enable the library target.
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
#[allow(clippy::all)]
#[allow(unused_unsafe)]
pub mod vmlinux;
