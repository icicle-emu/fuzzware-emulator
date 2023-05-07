use std::{
    io::Write,
    os::raw::{c_int, c_void},
};

use icicle_vm::{
    cpu::{
        debug_info::{DebugInfo, SourceLocation},
        mem::perm,
        CpuSnapshot, ExceptionCode, Hook,
    },
    VmExit,
};

use crate::{
    fuzzware::{uc_err::*, *},
    uc_err, Context, HookKind,
};

pub(crate) const DEBUG: bool = false;
pub(crate) const TRACE_MMIO_READS: bool = false;
pub(crate) const TRACE_PATHS: bool = false;
pub(crate) const SAVE_DISASM: bool = false;

macro_rules! debug {
    ($($arg:tt)*) => {{
        if DEBUG {
            eprintln!($($arg)*)
        }
    }}
}

pub fn uc_perms_to_icicle_perms(uc_perms: u32) -> u8 {
    let mut perm = perm::MAP;
    if uc_perms & uc_prot::UC_PROT_EXEC != 0 {
        perm |= perm::EXEC;
    }
    if uc_perms & uc_prot::UC_PROT_READ != 0 {
        perm |= perm::READ;
    }
    if uc_perms & uc_prot::UC_PROT_WRITE != 0 {
        perm |= perm::WRITE;
    }
    perm
}

pub fn icicle_perms_to_uc_perms(perm: u8) -> u32 {
    let mut uc_perm = 0;
    if perm & perm::EXEC != 0 {
        uc_perm |= uc_prot::UC_PROT_EXEC;
    }
    if perm & perm::READ != 0 {
        uc_perm |= uc_prot::UC_PROT_READ;
    }
    if perm & perm::WRITE != 0 {
        uc_perm |= uc_prot::UC_PROT_WRITE;
    }
    uc_perm
}

fn read_err_to_uc_err(err: icicle_vm::cpu::mem::MemError) -> uc_err {
    match err {
        icicle_vm::cpu::mem::MemError::Unmapped => UC_ERR_READ_UNMAPPED,
        icicle_vm::cpu::mem::MemError::ReadViolation => UC_ERR_READ_PROT,
        icicle_vm::cpu::mem::MemError::Unaligned => UC_ERR_READ_UNALIGNED,
        icicle_vm::cpu::mem::MemError::OutOfMemory => UC_ERR_NOMEM,
        _ => UC_ERR_EXCEPTION,
    }
}

#[allow(unused)]
fn write_err_to_uc_err(err: icicle_vm::cpu::mem::MemError) -> uc_err {
    match err {
        icicle_vm::cpu::mem::MemError::Unmapped => UC_ERR_WRITE_UNMAPPED,
        icicle_vm::cpu::mem::MemError::WriteViolation => UC_ERR_WRITE_PROT,
        icicle_vm::cpu::mem::MemError::Unaligned => UC_ERR_WRITE_UNALIGNED,
        icicle_vm::cpu::mem::MemError::OutOfMemory => UC_ERR_NOMEM,
        _ => UC_ERR_EXCEPTION,
    }
}

pub struct PathTracer {
    /// A list of (block address, icount, fuzz_offset) pairs tracking all blocks hit by the
    /// emulator.
    pub blocks: Vec<(u64, u64, u64)>,
}

impl PathTracer {
    pub fn new() -> Self {
        Self { blocks: vec![] }
    }
}

impl icicle_vm::cpu::Hook for PathTracer {
    fn call(&mut self, cpu: &mut icicle_vm::cpu::Cpu, pc: u64) {
        let fuzz_offset = unsafe { crate::fuzzware::fuzz_consumed() };
        self.blocks.push((pc, cpu.icount(), fuzz_offset as u64));
    }

    fn as_any(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

pub trait ExceptionHook {
    fn handle_exception(&mut self, addr: u64, kind: uc_mem_type::Type) -> bool;
}

// uc_engine *uc, uint32_t intno, void *user_data
type SyscallHook = unsafe extern "C" fn(*mut uc_engine, u32, *mut c_void);

// uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user_data
type MemCallback =
    unsafe extern "C" fn(*mut uc_engine, uc_mem_type::Type, u64, u32, u64, *mut c_void) -> u8;

#[derive(Clone)]
struct UnicornHook {
    vtable: *mut uc_engine, /* Super unsafe: we end up with multiple mutable references, however
                             * this saves a lot of code rewriting. */
    callback: *const c_void,
    userdata: *mut c_void,
}

impl ExceptionHook for UnicornHook {
    fn handle_exception(&mut self, addr: u64, kind: uc_mem_type::Type) -> bool {
        unsafe {
            let func_ptr: MemCallback = std::mem::transmute(self.callback);
            func_ptr(self.vtable, kind, addr, 1, 0, self.userdata) != 0
        }
    }
}

pub fn get_u64(value: &[u8]) -> u64 {
    match *value {
        [x0] => u8::from_le_bytes([x0]) as u64,
        [x0, x1] => u16::from_le_bytes([x0, x1]) as u64,
        [x0, x1, x2, x3] => u32::from_le_bytes([x0, x1, x2, x3]) as u64,
        [x0, x1, x2, x3, x4, x5, x6, x7] => u64::from_le_bytes([x0, x1, x2, x3, x4, x5, x6, x7]),
        _ => 0,
    }
}

impl icicle_vm::cpu::mem::WriteHook for UnicornHook {
    fn write(&mut self, _: &mut icicle_vm::cpu::Mmu, addr: u64, value: &[u8]) {
        let ty = uc_mem_type::UC_MEM_WRITE;
        unsafe {
            let func_ptr: MemCallback = std::mem::transmute(self.callback);
            func_ptr(self.vtable, ty, addr, value.len() as u32, get_u64(value), self.userdata);
        }
    }
}

impl icicle_vm::cpu::mem::ReadHook for UnicornHook {
    fn read(&mut self, _: &mut icicle_vm::cpu::Mmu, addr: u64, size: u8) {
        let ty = uc_mem_type::UC_MEM_READ;
        unsafe {
            let func_ptr: MemCallback = std::mem::transmute(self.callback);
            func_ptr(self.vtable, ty, addr, size as u32, 0, self.userdata);

            if TRACE_MMIO_READS && size == 4 {
                let ctx = &mut *{ &mut *self.vtable.as_mut().unwrap() }.ctx.cast::<Context>();
                let value = ctx.vm.cpu.mem.read_u32(addr, perm::NONE).unwrap();
                let pc = ctx.vm.cpu.read_pc();
                ctx.reads.push((addr, pc, value));
            }
        }
    }
}

impl icicle_vm::cpu::mem::ReadAfterHook for UnicornHook {
    fn read(&mut self, _: &mut icicle_vm::cpu::Mmu, addr: u64, value: &[u8]) {
        let ty = uc_mem_type::UC_MEM_READ_AFTER;
        unsafe {
            let func_ptr: MemCallback = std::mem::transmute(self.callback);
            func_ptr(self.vtable, ty, addr, value.len() as u32, get_u64(value), self.userdata);
        }
    }
}

// uc_engine *uc, uint64_t addr, int size, void *user_data
type BlockCallback = unsafe extern "C" fn(*mut uc_engine, u64, u32, *mut c_void) -> u8;

extern "sysv64" fn uc_call_translator(_: *mut icicle_vm::cpu::Cpu, addr: u64, userdata: *mut ()) {
    unsafe {
        let uc_hook = &mut *userdata.cast::<UnicornHook>();
        let func_ptr: BlockCallback = std::mem::transmute(uc_hook.callback);
        func_ptr(uc_hook.vtable, addr, 0, uc_hook.userdata);
    }
}

impl icicle_vm::cpu::Hook for UnicornHook {
    fn call(&mut self, _cpu: &mut icicle_vm::cpu::Cpu, addr: u64) {
        unsafe {
            let func_ptr: BlockCallback = std::mem::transmute(self.callback);
            func_ptr(self.vtable, addr, 0, self.userdata);
        }
    }

    fn as_ptr(
        &self,
    ) -> Option<(extern "sysv64" fn(*mut icicle_vm::cpu::Cpu, u64, *mut ()), *mut ())> {
        Some((uc_call_translator, (self as *const UnicornHook as *mut UnicornHook).cast()))
    }

    fn as_any(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

pub(crate) struct FuzzwareEnvironment {
    hooks: Vec<(u64, u64, uc_hook_type::Type, Box<dyn ExceptionHook>)>,
    last_fault_addr: u64,
    interrupt_ret_hook: Option<UnicornHook>,
    syscall_hook: Option<UnicornHook>,
    debug_info: DebugInfo,
}

impl FuzzwareEnvironment {
    pub fn new() -> Self {
        Self {
            hooks: vec![],
            last_fault_addr: 0,
            interrupt_ret_hook: None,
            syscall_hook: None,
            debug_info: DebugInfo::default(),
        }
    }

    pub fn set_debug_info(&mut self, path: &std::path::Path) -> Result<(), String> {
        tracing::info!("Using debug info from: {}", path.display());
        let file =
            std::fs::read(path).map_err(|e| format!("failed to read `{}`: {e}", path.display()))?;
        self.debug_info.add_file(&file, 0)?;
        Ok(())
    }

    pub fn add_mem_fault_hook(
        &mut self,
        start: u64,
        end: u64,
        kind: uc_hook_type::Type,
        hook: Box<dyn ExceptionHook>,
    ) -> Option<u32> {
        let next_id: u32 = self.hooks.len().try_into().unwrap();
        self.hooks.push((start, end, kind, hook));
        Some(next_id)
    }

    fn check_mem_fault_hooks(
        &mut self,
        cpu: &mut icicle_vm::cpu::Cpu,
        addr: u64,
        hook_kind: uc_hook_type::Type,
        mem_kind: uc_mem_type::Type,
    ) {
        if addr == self.last_fault_addr {
            // Double fault, prevent infinite loops.
            return;
        }
        self.last_fault_addr = addr;

        for (start, end, kind, hook) in &mut self.hooks {
            if start > end || (*start <= addr && addr < *end) {
                if *kind & hook_kind == hook_kind {
                    if hook.handle_exception(addr, mem_kind) {
                        cpu.exception.clear();
                    }
                }
            }
        }
    }

    fn handle_nvic_exception(&mut self, cpu: &mut icicle_vm::cpu::Cpu) {
        if let Some(hook) = self.interrupt_ret_hook.as_mut() {
            // Prevent the CPU from resuming the faulting instruction.
            cpu.exception.clear();
            cpu.block_id = u64::MAX;
            cpu.block_offset = 0;

            // Trigger the hook.
            hook.call(cpu, cpu.read_pc());
        }
    }
}

impl icicle_vm::cpu::Environment for FuzzwareEnvironment {
    fn load(&mut self, _: &mut icicle_vm::cpu::Cpu, _: &[u8]) -> Result<(), String> {
        Err("Fuzzware environment should not directly load the binary".into())
    }

    fn handle_exception(&mut self, cpu: &mut icicle_vm::cpu::Cpu) -> Option<VmExit> {
        match ExceptionCode::from_u32(cpu.exception.code) {
            ExceptionCode::ReadPerm | ExceptionCode::ReadUninitialized => {
                self.check_mem_fault_hooks(
                    cpu,
                    cpu.exception.value,
                    uc_hook_type::UC_HOOK_MEM_READ_PROT,
                    uc_mem_type::UC_MEM_READ_PROT,
                );
            }
            ExceptionCode::WritePerm => {
                self.check_mem_fault_hooks(
                    cpu,
                    cpu.exception.value,
                    uc_hook_type::UC_HOOK_MEM_WRITE_PROT,
                    uc_mem_type::UC_MEM_WRITE_PROT,
                );
            }
            ExceptionCode::Syscall => {
                if let Some(hook) = self.syscall_hook.as_mut() {
                    unsafe {
                        let func_ptr: SyscallHook = std::mem::transmute(hook.callback);
                        func_ptr(hook.vtable, crate::arm::EXCP_SWI, hook.userdata);
                    }
                }
            }
            ExceptionCode::ShadowStackInvalid => {
                if cpu.exception.value & NVIC_EXCEPT_MAGIC_RET_MASK == NVIC_EXCEPT_MAGIC_RET_MASK {
                    self.handle_nvic_exception(cpu);
                }
            }
            ExceptionCode::InvalidInstruction => {
                let pc = cpu.read_pc();
                if pc & NVIC_EXCEPT_MAGIC_RET_MASK == NVIC_EXCEPT_MAGIC_RET_MASK {
                    cpu.pop_shadow_stack(pc);
                    self.handle_nvic_exception(cpu);
                }
            }
            _ => {}
        }

        None
    }

    fn next_timer(&self) -> u64 {
        u64::MAX
    }

    fn snapshot(&mut self) -> Box<dyn std::any::Any> {
        Box::new(())
    }

    fn restore(&mut self, _snapshot: &Box<dyn std::any::Any>) {}

    fn as_any(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn symbolize_addr(
        &mut self,
        _cpu: &mut icicle_vm::cpu::Cpu,
        addr: u64,
    ) -> Option<SourceLocation> {
        self.debug_info.symbolize_addr(addr)
    }

    fn lookup_symbol(&mut self, symbol: &str) -> Option<u64> {
        // Note: we clear the thumb bit because the SLEIGH spec normalizes jumps to thumb addresses.
        self.debug_info.symbols.resolve_sym(symbol).map(|x| x & !0b1)
    }
}

pub unsafe extern "C" fn emu_start(
    ctx: *mut c_void,
    begin: u64,
    until: u64,
    timeout: u64,
    count: u64,
) -> uc_err {
    debug!("icicle_unicorn_api::emu_start({begin:#x}, {until:#x}, {timeout:#x}, {count:#x})");
    let ctx = &mut *ctx.cast::<Context>();
    ctx.vm.cpu.mem.tlb.clear();

    if TRACE_MMIO_READS {
        ctx.reads.clear();
    }

    if ctx.print_exit_info || TRACE_PATHS {
        let path_tracer = ctx.vm.cpu.get_hook_mut(ctx.path_tracer_hook);
        path_tracer.as_any().downcast_mut::<PathTracer>().unwrap().blocks.clear();
    }

    if ctx.kill_on_next_run {
        panic!("prior crash detected");
    }
    ctx.exec_count += 1;

    ctx.vm.cpu.write_pc(begin & !0b1);
    ctx.vm.cpu.set_isa_mode(1);
    ctx.vm.cpu.exception.clear();

    if count != 0 {
        ctx.vm.icount_limit = count;
    }
    if let Some(limit) = std::env::var("ICOUNT_LIMIT").ok() {
        ctx.vm.icount_limit = limit.parse().unwrap();
    }

    let exit = ctx.vm.run();
    maybe_save_disasm(ctx);
    if std::mem::take(&mut ctx.stop_requested) {
        if ctx.print_exit_info {
            save_exit_info(ctx, exit);
        }
        // Exit was requested by the fuzzer, so ignore the exit reason generated by the emulator.
        return UC_ERR_OK;
    }

    save_exit_info(ctx, exit);

    // ctx.kill_on_next_run = true;
    UC_ERR_EXCEPTION
}

fn maybe_save_disasm(ctx: &mut Context) {
    if ctx.last_block_count >= ctx.vm.code.blocks.len() || !SAVE_DISASM {
        return;
    }

    if ctx.last_block_count == 0 {
        let _ = std::fs::remove_dir_all("./disasm");
        let _ = std::fs::create_dir("./disasm");
    }

    ctx.last_block_count = ctx.vm.code.blocks.len();
    std::fs::write(
        format!("disasm/{:05}.asm", ctx.last_block_count),
        icicle_vm::debug::dump_disasm(&ctx.vm).unwrap().as_bytes(),
    )
    .unwrap();
    save_trace(ctx, format!("disasm/{:05}.trace.txt", ctx.last_block_count).as_ref(), false);
}

pub unsafe extern "C" fn save_info(ctx: *mut c_void) -> uc_err {
    let ctx = &mut *ctx.cast::<Context>();
    save_exit_info(ctx, VmExit::Running);
    UC_ERR_OK
}

fn save_exit_info(ctx: &mut Context, exit: VmExit) {
    let pc = ctx.vm.cpu.read_pc();
    if !ctx.crashing_addresses.insert(pc) && !ctx.print_exit_info {
        return;
    }

    eprintln!(
        "[{pc:#x}] VM exit: {exit:?}\n\ncallstack:\n{}\nregisters:\n{}\n",
        icicle_vm::debug::backtrace(&mut ctx.vm),
        icicle_vm::debug::print_regs(&ctx.vm, &icicle_vm::debug::get_debug_regs(&ctx.vm.cpu)),
    );

    if ctx.print_exit_info || TRACE_PATHS {
        save_trace(ctx, "full_trace.txt".as_ref(), true);
    }
    std::fs::write("crash_disasm.asm", icicle_vm::debug::dump_disasm(&ctx.vm).unwrap().as_bytes())
        .unwrap();

    if TRACE_MMIO_READS {
        let mut output = std::io::BufWriter::new(std::fs::File::create("mmio_reads.txt").unwrap());
        for (addr, pc, value) in &ctx.reads {
            writeln!(output, "{addr:#x},{pc:#0x},{value:#x}").unwrap();
        }
    }

    std::fs::write("tlb.txt", format!("{:#x?}", ctx.vm.cpu.mem.tlb)).unwrap();
}

fn save_trace(ctx: &mut Context, path: &std::path::Path, debug: bool) {
    let mut output = std::io::BufWriter::new(std::fs::File::create(path).unwrap());
    let path_tracer = ctx.vm.cpu.get_hook_mut(ctx.path_tracer_hook);
    let blocks = path_tracer.as_any().downcast_ref::<PathTracer>().unwrap().blocks.clone();
    for (addr, icount, fuzz_offset) in &blocks {
        writeln!(output, "{addr:#x},{icount},{fuzz_offset}").unwrap();
    }

    if debug {
        // Also print the final blocks to stderr
        let max_blocks_to_print =
            std::env::var("PRINT_FINAL_BLOCKS").ok().and_then(|x| x.parse().ok()).unwrap_or(10);
        eprintln!("Final blocks:");
        for (addr, icount, fuzz_offset) in blocks.iter().rev().take(max_blocks_to_print) {
            let location = ctx
                .vm
                .env
                .symbolize_addr(&mut ctx.vm.cpu, *addr)
                .unwrap_or(SourceLocation::default());
            eprintln!("{addr:#x}: {location} (icount = {icount}, input_offset = {fuzz_offset})");
        }
        eprintln!("");
    }
}

pub unsafe extern "C" fn emu_stop(ctx: *mut c_void) -> uc_err {
    debug!("icicle_unicorn_api::emu_stop");
    let ctx = &mut *ctx.cast::<Context>();
    ctx.vm.cpu.exception.code = ExceptionCode::Environment as u32;
    ctx.vm.cpu.exception.value = 1;

    // We might end up with an "uninitalized read" if this stop was requested from a `read_hook`, so
    // we set a flag to ensure we can check for this case when the emulator is stopping.
    ctx.stop_requested = true;
    UC_ERR_OK
}

pub unsafe extern "C" fn reg_read(ctx: *mut c_void, regid: c_int, value: *mut c_void) -> uc_err {
    // debug!("icicle_unicorn_api::reg_read({regid})");
    let ctx = &mut *ctx.cast::<Context>();
    match regid as u32 {
        uc_arm_reg::UC_ARM_REG_XPSR => *value.cast::<u32>() = crate::arm::read_xpsr(ctx),
        _ => {
            let data = match ctx.get_reg_slice(regid) {
                Some(slice) => slice,
                None => panic!("read to invalid register: {regid}"),
            };
            std::ptr::copy_nonoverlapping(data.as_ptr(), value.cast(), data.len());
        }
    };
    UC_ERR_OK
}

pub unsafe extern "C" fn reg_read_batch(
    ctx: *mut c_void,
    regs: *mut c_int,
    vals: *mut *mut c_void,
    count: c_int,
) -> uc_err {
    let regs = std::slice::from_raw_parts(regs, count as usize);
    let vals = std::slice::from_raw_parts_mut(vals, count as usize);

    debug!("icicle_unicorn_api::reg_read_batch({regs:?})");

    for (regid, val) in regs.iter().zip(vals) {
        let result = reg_read(ctx, *regid, *val);
        if result != UC_ERR_OK {
            return result;
        }
    }

    UC_ERR_OK
}

pub unsafe extern "C" fn reg_write(ctx: *mut c_void, regid: c_int, value: *const c_void) -> uc_err {
    debug!("icicle_unicorn_api::reg_write({regid})");
    let ctx = &mut *ctx.cast::<Context>();

    match regid as u32 {
        uc_arm_reg::UC_ARM_REG_PC => {
            let new_pc = (*value.cast::<u32>() & !0b1) as u64;
            ctx.vm.cpu.set_isa_mode(1);
            ctx.vm.cpu.exception.code = ExceptionCode::ExternalAddr as u32;
            ctx.vm.cpu.exception.value = new_pc;
            ctx.vm.cpu.write_pc(new_pc);
        }
        uc_arm_reg::UC_ARM_REG_XPSR => crate::arm::write_xpsr(ctx, *value.cast::<u32>()),
        _ => {
            let data = match ctx.get_reg_slice(regid) {
                Some(slice) => slice,
                None => panic!("read to invalid register: {regid}"),
            };
            std::ptr::copy_nonoverlapping(value.cast(), data.as_mut_ptr(), data.len());
        }
    }

    UC_ERR_OK
}

pub unsafe extern "C" fn reg_write_batch(
    ctx: *mut c_void,
    regs: *mut c_int,
    vals: *const *mut c_void,
    count: c_int,
) -> uc_err {
    let regs = std::slice::from_raw_parts(regs, count as usize);
    let vals = std::slice::from_raw_parts(vals, count as usize);
    debug!("icicle_unicorn_api::reg_write_batch({regs:?})");

    for (regid, val) in regs.iter().zip(vals) {
        let result = reg_write(ctx, *regid, *val);
        if result != UC_ERR_OK {
            return result;
        }
    }

    UC_ERR_OK
}

pub unsafe extern "C" fn reg_ptr(
    ctx: *mut c_void,
    regid: c_int,
    value: *mut *mut c_void,
) -> uc_err {
    debug!("icicle_unicorn_api::reg_ptr({regid})");
    let ctx = &mut *ctx.cast::<Context>();
    let data = match ctx.get_reg_slice(regid) {
        Some(slice) => slice,
        None => return UC_ERR_ARG,
    };
    *value = data.as_mut_ptr().cast();
    UC_ERR_OK
}

pub unsafe extern "C" fn mem_read(
    ctx: *mut c_void,
    address: u64,
    buf: *mut c_void,
    count: usize,
) -> uc_err {
    // debug!("icicle_unicorn_api::mem_read");
    let ctx = &mut *ctx.cast::<Context>();
    match count {
        1 => match ctx.vm.cpu.mem.read_u8(address, perm::NONE) {
            Ok(x) => *buf.cast() = x,
            Err(e) => return read_err_to_uc_err(e),
        },
        2 => match ctx.vm.cpu.mem.read_u16(address, perm::NONE) {
            Ok(x) => *buf.cast() = x,
            Err(e) => return read_err_to_uc_err(e),
        },
        4 => match ctx.vm.cpu.mem.read_u32(address, perm::NONE) {
            Ok(x) => *buf.cast() = x,
            Err(e) => return read_err_to_uc_err(e),
        },
        8 => match ctx.vm.cpu.mem.read_u64(address, perm::NONE) {
            Ok(x) => *buf.cast() = x,
            Err(e) => return read_err_to_uc_err(e),
        },
        _ => {
            let buf = std::slice::from_raw_parts_mut(buf.cast::<u8>(), count);
            if let Err(e) = ctx.vm.cpu.mem.read_bytes(address, buf, perm::NONE) {
                return read_err_to_uc_err(e);
            }
        }
    }
    UC_ERR_OK
}

pub unsafe extern "C" fn mem_write(
    ctx: *mut c_void,
    address: u64,
    buf: *const c_void,
    count: usize,
) -> uc_err {
    debug!("icicle_unicorn_api::mem_write({address:#0x})");
    let ctx = &mut *ctx.cast::<Context>();
    let result = match count {
        1 => ctx.vm.cpu.mem.write_u8(address, *buf.cast(), perm::NONE),
        2 => ctx.vm.cpu.mem.write_u16(address, *buf.cast(), perm::NONE),
        4 => ctx.vm.cpu.mem.write_u32(address, *buf.cast(), perm::NONE),
        8 => ctx.vm.cpu.mem.write_u64(address, *buf.cast(), perm::NONE),
        _ => {
            let buf = std::slice::from_raw_parts(buf.cast::<u8>(), count);
            ctx.vm.cpu.mem.write_bytes(address, buf, perm::NONE)
        }
    };
    // Fuzzware seems to not check errors, so just panic here instead.
    result.expect("mem_write failed");
    UC_ERR_OK
}

pub unsafe extern "C" fn mem_set(ctx: *mut c_void, address: u64, value: u8, size: usize) -> uc_err {
    debug!("icicle_unicorn_api::mem_set({address:#0x}, {value:#0x}, {size:#0x}");
    let ctx = &mut *ctx.cast::<Context>();

    // Fuzzware seems to not check errors, so just panic here instead.
    ctx.vm.cpu.mem.fill_mem(address, size as u64, value).expect("mem_set failed");
    UC_ERR_OK
}

pub unsafe extern "C" fn mem_protect(
    ctx: *mut c_void,
    address: u64,
    size: usize,
    perms: u32,
) -> uc_err {
    let ctx = &mut *ctx.cast::<Context>();
    let perms = uc_perms_to_icicle_perms(perms);
    debug!("icicle_unicorn_api::mem_protect({address:#x}, {size:#x}, {})", perm::display(perms));
    if let Err(e) = ctx.vm.cpu.mem.update_perm(address, size as u64, perms) {
        return read_err_to_uc_err(e);
    }
    UC_ERR_OK
}

pub unsafe extern "C" fn mem_regions(
    ctx: *mut c_void,
    regions: *mut *mut uc_mem_region,
    count: *mut u32,
) -> uc_err {
    debug!("icicle_unicorn_api::mem_regions");
    let ctx = &mut *ctx.cast::<Context>();

    let mut out = vec![];
    for (start, end, kind) in ctx.vm.cpu.mem.mapping.iter() {
        debug!("start={start:#0x}, end={end:#x}, kind={kind:?}");
        match kind {
            icicle_vm::cpu::mem::MemoryMapping::Physical(page) => {
                let icicle_perm = ctx.vm.cpu.mem.get_physical(page.index).data().perm
                    [(start - page.addr) as usize];
                out.push(uc_mem_region {
                    begin: start,
                    end: end - 1, // Unicorn API expects inclusive ranges
                    perms: icicle_perms_to_uc_perms(icicle_perm),
                });
            }
            icicle_vm::cpu::mem::MemoryMapping::Unallocated(region) => {
                out.push(uc_mem_region {
                    begin: start,
                    end: end - 1,
                    perms: icicle_perms_to_uc_perms(region.perm),
                });
            }
            _ => {}
        }
    }

    *count = out.len() as u32;
    *regions = Vec::leak(out).as_mut_ptr();

    UC_ERR_OK
}

pub unsafe extern "C" fn block_hook_add(
    ctx: *mut c_void,
    hh: *mut uc_hook,
    kind: c_int,
    callback: *mut c_void,
    userdata: *mut c_void,
    begin: u64,
    end: u64,
) -> uc_err {
    debug!(
        "icicle_unicorn_api::block_hook_add(kind={kind}, callback={callback:p}, \
            userdata={userdata:p}, begin={begin:#x}, end={end:#x})"
    );
    let ctx = &mut *ctx.cast::<Context>();

    let (begin, end) = if begin > end { (0, u64::MAX) } else { (begin, end) };
    let vtable = (*ctx).vtable.as_mut().unwrap().as_mut() as *mut uc_engine;
    let hook = UnicornHook { vtable, callback, userdata };

    if begin == NVIC_EXCEPT_MAGIC_RET_MASK {
        let env = ctx.vm.env.as_any().downcast_mut::<FuzzwareEnvironment>().unwrap();
        env.interrupt_ret_hook = Some(hook);
        *hh = ctx.register_hook(HookKind::InterruptRetHook);
    }
    else {
        let hook_id = ctx.vm.cpu.add_hook(Box::new(hook));
        let injector_id =
            icicle_vm::injector::register_block_hook_injector(&mut ctx.vm, begin, end, hook_id);
        *hh = ctx.register_hook(HookKind::Block { injector_id });
    }

    UC_ERR_OK
}

pub unsafe extern "C" fn mem_hook_add(
    ctx: *mut c_void,
    hh: *mut uc_hook,
    kind: c_int,
    callback: *mut c_void,
    userdata: *mut c_void,
    begin: u64,
    end: u64,
) -> uc_err {
    let kind = kind as uc_hook_type::Type;
    debug!(
        "icicle_unicorn_api::mem_hook_add(kind={kind}, callback={callback:p}, \
            userdata={userdata:p}, begin={begin:#x}, end={end:#x})"
    );
    let ctx = ctx.cast::<Context>();

    let vtable = (*ctx).vtable.as_mut().unwrap().as_mut() as *mut uc_engine;
    let hook = UnicornHook { vtable, callback, userdata };

    *hh = match (*ctx).add_mem_hook(kind, begin, end, hook) {
        Some(id) => id,
        None => return UC_ERR_HOOK,
    };
    UC_ERR_OK
}

pub unsafe extern "C" fn int_hook_add(
    ctx: *mut c_void,
    hh: *mut uc_hook,
    _kind: c_int,
    callback: *mut c_void,
    userdata: *mut c_void,
    _begin: u64,
    _end: u64,
) -> uc_err {
    debug!("icicle_unicorn_api::int_hook_add");

    let ctx = &mut *ctx.cast::<Context>();
    let vtable = (*ctx).vtable.as_mut().unwrap().as_mut() as *mut uc_engine;
    let hook = UnicornHook { vtable, callback, userdata };

    let env = ctx.vm.env.as_any().downcast_mut::<FuzzwareEnvironment>().unwrap();
    env.syscall_hook = Some(hook);
    *hh = ctx.register_hook(HookKind::SyscallHook);

    UC_ERR_OK
}

pub unsafe extern "C" fn hook_del(ctx: *mut c_void, hh: uc_hook) -> uc_err {
    debug!("icicle_unicorn_api::hook_del({hh})");
    let ctx = &mut *ctx.cast::<Context>();
    let hook = match ctx.hooks.remove(&hh) {
        Some(hook) => hook,
        None => return UC_ERR_HANDLE,
    };

    match hook {
        HookKind::Mem { read, read_after, write, fault } => {
            if let Some(_fault) = fault {
                let _env = ctx.vm.env.as_any().downcast_mut::<FuzzwareEnvironment>().unwrap();
                // @todo: remove hook.
            }
            if let Some(_hook) = read {
                // @todo!
            }
            if let Some(_hook) = read_after {
                // @todo!
            }
            if let Some(_hook) = write {
                // @todo!
            }
        }
        HookKind::Block { injector_id: _ } => {
            // @todo
        }
        HookKind::InterruptRetHook => {
            let env = ctx.vm.env.as_any().downcast_mut::<FuzzwareEnvironment>().unwrap();
            env.interrupt_ret_hook = None;
        }
        HookKind::SyscallHook => {
            let env = ctx.vm.env.as_any().downcast_mut::<FuzzwareEnvironment>().unwrap();
            env.syscall_hook = None;
        }
    }
    UC_ERR_OK
}

pub unsafe extern "C" fn context_alloc(ctx: *mut c_void, context: *mut *mut uc_context) -> uc_err {
    debug!("icicle_unicorn_api::context_alloc");
    let ctx = &mut *ctx.cast::<Context>();
    let ptr = Box::leak(Box::new(ctx.vm.cpu.snapshot()));
    *context = (ptr as *mut CpuSnapshot).cast::<uc_context>();
    UC_ERR_OK
}

pub unsafe extern "C" fn context_save(ctx: *mut c_void, context: *mut uc_context) -> uc_err {
    debug!("icicle_unicorn_api::context_save");
    let ctx = &mut *ctx.cast::<Context>();
    *context.cast::<CpuSnapshot>() = ctx.vm.cpu.snapshot();
    UC_ERR_OK
}

pub unsafe extern "C" fn context_restore(ctx: *mut c_void, context: *mut uc_context) -> uc_err {
    debug!("icicle_unicorn_api::context_restore");
    let ctx = &mut *ctx.cast::<Context>();
    ctx.vm.cpu.mem.tlb.clear();
    ctx.vm.cpu.restore(&*context.cast::<CpuSnapshot>());
    UC_ERR_OK
}

pub unsafe extern "C" fn free(ctx: *mut c_void) -> uc_err {
    debug!("icicle_unicorn_api::free");
    let _ctx = &mut *ctx.cast::<Context>();
    // @fixme we never free memory
    UC_ERR_OK
}

pub unsafe extern "C" fn fuzzer_init_cov(
    ctx: *mut c_void,
    bitmap: *mut c_void,
    map_size: u32,
) -> uc_err {
    debug!("icicle_unicorn_api::fuzzer_init_cov({bitmap:p},{map_size:#x})");
    let ctx = &mut *ctx.cast::<Context>();

    let context_bits = match std::env::var("ICICLE_CONTEXT_BITS") {
        Ok(bits) => bits.parse().unwrap(),
        Err(_) => 0,
    };

    let store_ref = match std::env::var("ICICLE_BLOCK_COVERAGE_ONLY").ok() {
        Some(_) => icicle_fuzzing::coverage::BlockCoverageBuilder::new()
            .enable_context(context_bits != 0)
            .finish(&mut ctx.vm, bitmap.cast(), map_size),
        None => icicle_fuzzing::coverage::AFLHitCountsBuilder::new()
            .with_context(context_bits)
            .finish(&mut ctx.vm, bitmap.cast(), map_size),
    };

    if let Some(level) = std::env::var("AFL_COMPCOV_LEVEL").ok() {
        let level = level.parse::<u8>().expect("Invalid value for AFL_COMPCOV_LEVEL");
        tracing::info!("AFL_COMPCOV_LEVEL = {level}");
        icicle_fuzzing::compcov::CompCovBuilder::new().level(level).finish(&mut ctx.vm, store_ref);
    }

    ctx.coverage_bitmap = Some((bitmap.cast(), map_size));
    ctx.prev_pc_var = ctx.vm.cpu.arch.sleigh.get_reg("afl.prev_pc").map(|x| x.var);
    ctx.context_var = ctx.vm.cpu.arch.sleigh.get_reg("afl.context").map(|x| x.var);

    UC_ERR_OK
}

pub unsafe extern "C" fn fuzzer_reset_cov(ctx: *mut c_void, do_clear: c_int) -> uc_err {
    debug!("icicle_unicorn_api::fuzzer_reset_cov({do_clear})");
    let ctx = &mut *ctx.cast::<Context>();
    let (ptr, size) = match ctx.coverage_bitmap {
        Some(value) => value,
        None => return UC_ERR_ARG,
    };
    if do_clear != 0 {
        std::slice::from_raw_parts_mut(ptr, size as usize).fill(0);
    }
    if let Some(prev_pc) = ctx.prev_pc_var {
        ctx.vm.cpu.write_reg(prev_pc, 0_u16);
    }
    if let Some(context) = ctx.context_var {
        ctx.vm.cpu.write_reg(context, 0_u16);
    }

    UC_ERR_OK
}
