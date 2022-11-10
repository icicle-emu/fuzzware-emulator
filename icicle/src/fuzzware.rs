#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/fuzzware_bindings.rs"));

pub const NVIC_EXCEPT_MAGIC_RET_MASK: u64 = 0xfffffff0;

pub const ANY_MEM_HOOK: uc_hook_type::Type = uc_hook_type::UC_HOOK_MEM_WRITE
    | uc_hook_type::UC_HOOK_MEM_READ
    | uc_hook_type::UC_HOOK_MEM_READ_AFTER
    | uc_hook_type::UC_HOOK_MEM_WRITE_PROT
    | uc_hook_type::UC_HOOK_MEM_READ_PROT;

pub const ANY_BLOCK_HOOK: uc_hook_type::Type =
    uc_hook_type::UC_HOOK_BLOCK | uc_hook_type::UC_HOOK_BLOCK_UNCONDITIONAL;
