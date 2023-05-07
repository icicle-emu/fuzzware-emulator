#![feature(backtrace)]

pub mod fuzzware;

mod arm;
mod unicorn_api;

use std::{
    cell::UnsafeCell,
    collections::{HashMap, HashSet},
};

use icicle_vm::{
    cpu::{
        mem::{perm, Mapping, ReadAfterHook, ReadHook, WriteHook},
        Cpu,
    },
    Vm,
};

use once_cell::sync::Lazy;
use pyo3::{exceptions::PyValueError, prelude::*, types::PyByteArray, AsPyPointer};

use crate::{
    fuzzware::{uc_hook, uc_hook_type},
    unicorn_api::{get_u64, uc_perms_to_icicle_perms, FuzzwareEnvironment},
};

#[allow(non_camel_case_types)]
type uc_err = fuzzware::uc_err::Type;

fn into_py_err(err: impl std::fmt::Display) -> PyErr {
    PyValueError::new_err(err.to_string())
}

#[allow(unused)]
pub(crate) enum HookKind {
    Mem { read: Option<u32>, read_after: Option<u32>, write: Option<u32>, fault: Option<u32> },
    Block { injector_id: usize },
    InterruptRetHook,
    SyscallHook,
}

pub(crate) struct Context {
    pub vm: Vm,
    pub uc_vars: Vec<pcode::VarNode>,
    pub regs: arm::SpecialRegs,
    py_callbacks: Vec<(PyObject, Option<PyObject>)>,
    py_default_mmio_user_data: Option<PyObject>,
    vtable: Option<Box<fuzzware::uc_engine>>,

    path_tracer_hook: pcode::HookId,
    print_exit_info: bool,
    kill_on_next_run: bool,
    stop_requested: bool,
    exec_count: usize,

    next_hook_id: usize,
    hooks: HashMap<usize, HookKind>,
    coverage_bitmap: Option<(*mut u8, u32)>,
    prev_pc_var: Option<pcode::VarNode>,
    context_var: Option<pcode::VarNode>,
    crashing_addresses: HashSet<u64>,

    reads: Vec<(u64, u64, u32)>,
    last_block_count: usize,
}

impl Context {
    pub fn new(disable_shadow_stack: bool) -> PyResult<Self> {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_env("ICICLE_LOG"))
            .without_time()
            .init();

        std::env::set_var("ICICLE_ENABLE_JIT_VERIFIER", "false");
        let mut config = icicle_vm::cpu::Config::from_target_triple("arm-none");

        let disable_shadow_stack = std::env::var("ICICLE_DISABLE_SHADOW_STACK")
            .ok()
            .map_or(disable_shadow_stack, |x| x == "1");
        config.enable_shadow_stack = !disable_shadow_stack;
        let mut vm = icicle_vm::build(&config).map_err(into_py_err)?;

        arm::add_arm_extras(&mut vm);
        let vars = arm::map_uc_to_varnodes(&vm);
        let regs = arm::SpecialRegs::get(&mut vm);

        vm.env = Box::new(unicorn_api::FuzzwareEnvironment::new());

        let path_tracer_hook = vm.cpu.add_hook(Box::new(unicorn_api::PathTracer::new()));

        Ok(Self {
            vm,
            regs,
            py_callbacks: vec![],
            py_default_mmio_user_data: None,
            uc_vars: vars,
            vtable: None,
            path_tracer_hook,
            print_exit_info: false,
            kill_on_next_run: false,
            stop_requested: false,
            next_hook_id: 0,
            exec_count: 0,
            hooks: HashMap::new(),
            coverage_bitmap: None,
            prev_pc_var: None,
            context_var: None,
            crashing_addresses: HashSet::new(),
            reads: vec![],
            last_block_count: 0,
        })
    }

    pub fn register_hook(&mut self, kind: HookKind) -> usize {
        self.hooks.insert(self.next_hook_id, kind);
        self.next_hook_id += 1;
        self.next_hook_id - 1
    }

    pub fn add_mem_hook<H>(
        &mut self,
        kind: uc_hook_type::Type,
        begin: u64,
        end: u64,
        hook: H,
    ) -> Option<usize>
    where
        H: Clone + WriteHook + ReadHook + ReadAfterHook + unicorn_api::ExceptionHook + 'static,
    {
        // @fixme: clean up partially created hooks on failure.

        let mut write = None;
        if kind & uc_hook_type::UC_HOOK_MEM_WRITE != 0 {
            write = Some(self.vm.cpu.mem.add_write_hook(begin, end, Box::new(hook.clone()))?);
        }

        let mut read = None;
        if kind & uc_hook_type::UC_HOOK_MEM_READ != 0 {
            read = Some(self.vm.cpu.mem.add_read_hook(begin, end, Box::new(hook.clone()))?);
        }

        let mut read_after = None;
        if kind & uc_hook_type::UC_HOOK_MEM_READ_AFTER != 0 {
            read_after =
                Some(self.vm.cpu.mem.add_read_after_hook(begin, end, Box::new(hook.clone()))?);
        }

        let mut fault = None;
        if kind & uc_hook_type::UC_HOOK_MEM_WRITE_PROT != 0
            || kind & uc_hook_type::UC_HOOK_MEM_READ_PROT != 0
        {
            let env = self.vm.env.as_any().downcast_mut::<FuzzwareEnvironment>().unwrap();
            fault = Some(env.add_mem_fault_hook(begin, end, kind, Box::new(hook))?)
        }

        Some(self.register_hook(HookKind::Mem { read, read_after, write, fault }))
    }

    pub fn add_block_hook<H>(&mut self, begin: u64, end: u64, hook: H) -> Option<usize>
    where
        H: icicle_vm::cpu::Hook + 'static,
    {
        let hook_id = self.vm.cpu.add_hook(Box::new(hook));
        let injector_id =
            icicle_vm::injector::register_block_hook_injector(&mut self.vm, begin, end, hook_id);
        Some(self.register_hook(HookKind::Block { injector_id }))
    }

    pub fn get_reg_slice(&mut self, regid: i32) -> Option<&mut [u8]> {
        let var = *self.uc_vars.get(regid as usize)?;
        if var == pcode::VarNode::NONE {
            // Print backtrace so we know where in fuzzware
            eprintln!(
                "No Icicle variable found for regid={regid}\n{}",
                std::backtrace::Backtrace::force_capture(),
            );
        }
        self.vm.cpu.regs.get_mut(var)
    }

    // Super unsafe: creates a self referencing struct.
    unsafe fn build_vtable(&mut self) {
        use unicorn_api::*;
        let vtable = Box::new(fuzzware::uc_engine {
            ctx: (self as *mut Context).cast(),
            emu_start: Some(emu_start),
            emu_stop: Some(emu_stop),
            reg_read: Some(reg_read),
            reg_read_batch: Some(reg_read_batch),
            reg_write: Some(reg_write),
            reg_write_batch: Some(reg_write_batch),
            reg_ptr: Some(reg_ptr),
            mem_read: Some(mem_read),
            mem_write: Some(mem_write),
            mem_set: Some(mem_set),
            mem_protect: Some(mem_protect),
            mem_regions: Some(mem_regions),
            block_hook_add: Some(block_hook_add),
            mem_hook_add: Some(mem_hook_add),
            int_hook_add: Some(int_hook_add),
            hook_del: Some(hook_del),
            context_alloc: Some(context_alloc),
            context_save: Some(context_save),
            context_restore: Some(context_restore),
            free: Some(free),
            fuzzer_init_cov: Some(fuzzer_init_cov),
            fuzzer_reset_cov: Some(fuzzer_reset_cov),
            save_info: Some(save_info),
        });
        self.vtable = Some(vtable);
    }
}

#[pyclass(dict, unsendable)]
pub struct Uc {
    ctx: UnsafeCell<Box<Context>>,
}

impl Uc {
    unsafe fn uc_ptr(&self) -> *mut fuzzware::uc_engine {
        (*self.ctx.get()).vtable.as_mut().unwrap().as_mut()
    }
}

#[pymethods]
impl Uc {
    #[new]
    fn new(arch: i32, mode: u32, disable_shadow_stack: bool) -> PyResult<Self> {
        eprintln!("Uc.__init__({arch}, {mode}, {disable_shadow_stack})");
        let mut ctx = Box::new(Context::new(disable_shadow_stack)?);
        unsafe { ctx.build_vtable() };

        let vtable = ctx.vtable.as_mut().unwrap().as_mut() as *mut fuzzware::uc_engine;
        eprintln!("ctx: {ctx:p}, vtable: {vtable:p}");

        Ok(Self { ctx: UnsafeCell::new(ctx) })
    }

    #[args(timeout = "0", count = "0")]
    fn emu_start(&mut self, _begin: u64, _until: u64, _timeout: u64, _count: u64) -> PyResult<()> {
        Err(PyValueError::new_err("unimplemented: emu_start"))
    }

    fn emu_stop(&mut self) -> PyResult<()> {
        Err(PyValueError::new_err("unimplemented: emu_stop"))
    }

    #[args(opt = "None")]
    fn reg_read(&self, regid: i32, _opt: Option<&str>) -> PyResult<u64> {
        let value = unsafe { &mut *self.ctx.get() }
            .get_reg_slice(regid)
            .ok_or_else(|| PyValueError::new_err(format!("Unknown register: {regid}")))?;
        Ok(get_u64(value))
    }

    fn reg_write(&self, regid: i32, value: u64) -> PyResult<()> {
        eprintln!("Uc.reg_write({regid}, {value:#x})");
        let dst = unsafe { &mut *self.ctx.get() }
            .get_reg_slice(regid)
            .ok_or_else(|| PyValueError::new_err(format!("Unknown register: {regid}")))?;
        dst.copy_from_slice(&value.to_le_bytes()[..dst.len()]);
        Ok(())
    }

    fn mem_read<'py>(
        &self,
        py: Python<'py>,
        address: u64,
        size: u64,
    ) -> PyResult<&'py PyByteArray> {
        eprintln!("Uc.mem_read({address:#x}, {size:#x})");
        let mut buf = vec![0; size as usize];
        unsafe { &mut *self.ctx.get() }
            .vm
            .cpu
            .mem
            .read_bytes(address, &mut buf, perm::NONE)
            .map_err(into_py_err)?;
        Ok(PyByteArray::new(py, &buf))
    }

    fn mem_write(&mut self, address: u64, data: &[u8]) -> PyResult<()> {
        eprintln!("Uc.mem_write({address:#x}, {:#x})", data.len());
        self.ctx.get_mut().vm.cpu.mem.write_bytes(address, data, perm::NONE).map_err(into_py_err)
    }

    #[args(perms = "fuzzware::uc_prot::UC_PROT_ALL")]
    fn mem_map(&mut self, address: u64, size: u64, perms: u32) -> PyResult<()> {
        let perms = uc_perms_to_icicle_perms(perms);
        eprintln!("Uc.mem_map({address:#x}, {size:#x}, {})", perm::display(perms));
        if !self
            .ctx
            .get_mut()
            .vm
            .cpu
            .mem
            .map_memory(address, address + size, Mapping { perm: perms | perm::INIT, value: 0x0 })
        {
            return Err(PyValueError::new_err("map_memory failed"));
        }
        Ok(())
    }

    fn mem_map_ptr(&mut self, _address: u64, _size: u64, _perms: u64, _ptr: u64) -> PyResult<()> {
        Err(PyValueError::new_err("unimplemented: mem_map_ptr"))
    }

    fn mem_unmap(&mut self, _address: u64, _size: u64) -> PyResult<()> {
        Err(PyValueError::new_err("unimplemented: mem_unmap"))
    }

    #[args(perms = "fuzzware::uc_prot::UC_PROT_ALL")]
    fn mem_protect(&mut self, address: u64, size: u64, perms: u32) -> PyResult<()> {
        let perms = uc_perms_to_icicle_perms(perms);
        eprintln!("Uc.mem_protect({address:#x}, {size:#x}, {})", perm::display(perms));
        self.ctx.get_mut().vm.cpu.mem.update_perm(address, size, perms).map_err(into_py_err)
    }

    fn query(&mut self, _query_mode: u64) -> PyResult<()> {
        Err(PyValueError::new_err("unimplemented: query"))
    }

    #[args(begin = "1", end = "0", _arg1 = "0")]
    fn hook_add<'py>(
        mut self_: PyRefMut<'py, Self>,
        htype: uc_hook_type::Type,
        callback: PyObject,
        user_data: Option<PyObject>,
        begin: u64,
        end: u64,
        _arg1: u64,
    ) -> PyResult<usize> {
        eprintln!(
            "Uc.hook_add(htype={htype}, callback={callback:?}, \
                userdata={user_data:?}, begin={begin:#x}, end={end:#x})"
        );

        let id = self_.ctx.get_mut().py_callbacks.len();
        self_.ctx.get_mut().py_callbacks.push((callback, user_data));

        let hook = PythonHook { uc: self_.as_ptr(), id };
        if htype & fuzzware::ANY_MEM_HOOK != 0 {
            return self_
                .ctx
                .get_mut()
                .add_mem_hook(htype, begin, end, hook)
                .ok_or_else(|| PyValueError::new_err("Failed to add mem hook"));
        }

        if htype & fuzzware::ANY_BLOCK_HOOK != 0 {
            return self_
                .ctx
                .get_mut()
                .add_block_hook(begin, end, hook)
                .ok_or_else(|| PyValueError::new_err("Failed to add block hook"));
        }

        Err(PyValueError::new_err(format!("unimplemented: hook_add: {htype}")))
    }

    fn set_debug_file(&mut self, path: String) -> PyResult<()> {
        let env = self.ctx.get_mut().vm.env.as_any().downcast_mut::<FuzzwareEnvironment>().unwrap();
        env.set_debug_info(path.as_ref()).map_err(|e| PyValueError::new_err(e))
    }

    fn native_init<'py>(
        &mut self,
        py: Python<'py>,
        py_exit_hook: Option<PyObject>,
        mmio_regions: Vec<(u64, u64)>,
        py_default_mmio_user_data: PyObject,
        mut exit_at_bbls: Vec<u64>,
        exit_at_hit_num: u32,
        p_do_print_exit_info: i32,
        fuzz_consumption_timeout: u64,
        p_instr_limit: u64,
    ) -> PyResult<uc_err> {
        let print_exit_info = p_do_print_exit_info != 0;
        self.ctx.get_mut().print_exit_info = print_exit_info;

        if print_exit_info || unicorn_api::TRACE_PATHS {
            let ctx = self.ctx.get_mut();
            icicle_vm::injector::register_block_hook_injector(
                &mut ctx.vm,
                0,
                u64::MAX,
                ctx.path_tracer_hook,
            );
        }

        eprintln!(
            "Uc.native_init({py_exit_hook:0x?}, {mmio_regions:x?}, {py_default_mmio_user_data:?}, {exit_at_bbls:0x?}, {print_exit_info}, {fuzz_consumption_timeout}, {p_instr_limit})",
        );
        eprintln!("emulator pid = {}", std::process::id());
        let mut starts: Vec<u64> = mmio_regions.iter().map(|(s, _)| *s).collect();
        let mut ends: Vec<u64> = mmio_regions.iter().map(|(_, e)| *e).collect();

        let exit_hook = py_exit_hook.map(|hook| {
            *PY_EXIT_HOOK.lock().unwrap() = Some(hook);
            call_python_exit_hook as ExitHookNonNull
        });

        let result = unsafe {
            fuzzware::init(
                self.uc_ptr(),
                exit_hook,
                mmio_regions.len() as i32,
                starts.as_mut_ptr(),
                ends.as_mut_ptr(),
                py_default_mmio_user_data.as_ref(py).as_ptr() as *mut _,
                exit_at_bbls.len() as u32,
                exit_at_bbls.as_mut_ptr(),
                exit_at_hit_num,
                p_do_print_exit_info,
                fuzz_consumption_timeout,
                p_instr_limit,
            )
        };

        // Keep around user_data to prevent it from being GCed by the python runtime.
        self.ctx.get_mut().py_default_mmio_user_data = Some(py_default_mmio_user_data);

        Ok(result)
    }

    fn native_init_timer_hook(&mut self, global_timer_scale: u32) -> PyResult<uc_err> {
        eprintln!("Uc.init_timer_hook({global_timer_scale})");
        let result = unsafe { fuzzware::init_timer_hook(self.uc_ptr(), global_timer_scale) };
        Ok(result)
    }

    fn native_init_systick(&mut self, reload_val: u32) -> PyResult<uc_err> {
        eprintln!("Uc.native_init_systick({reload_val})");
        let result = unsafe { fuzzware::init_systick(self.uc_ptr(), reload_val) };
        Ok(result)
    }

    fn native_add_interrupt_trigger(
        &mut self,
        addr: u64,
        irq: u32,
        num_skips: u32,
        num_pends: u32,
        fuzz_mode: u32,
        trigger_mode: u32,
        every_nth_tick: u64,
    ) -> PyResult<uc_hook> {
        eprintln!(
            "Uc.add_interrupt_trigger({addr:#x}, {irq}, {num_skips}, {num_pends}, {fuzz_mode}, {trigger_mode}, {every_nth_tick})"
        );
        let result = unsafe {
            fuzzware::add_interrupt_trigger(
                self.uc_ptr(),
                addr,
                irq,
                num_skips,
                num_pends,
                fuzz_mode,
                trigger_mode,
                every_nth_tick,
            )
        };
        Ok(result)
    }

    fn native_register_py_handled_mmio_ranges(&mut self) -> PyResult<()> {
        todo!()
    }

    fn native_register_linear_mmio_models(
        &mut self,
        mut starts: Vec<u64>,
        mut ends: Vec<u64>,
        mut pcs: Vec<u32>,
        mut init_vals: Vec<u32>,
        mut steps: Vec<u32>,
    ) -> PyResult<uc_err> {
        let count = starts.len();
        assert!(
            ends.len() == count
                && pcs.len() == count
                && init_vals.len() == count
                && steps.len() == count
        );
        unsafe {
            Ok(fuzzware::register_linear_mmio_models(
                self.uc_ptr(),
                starts.as_mut_ptr(),
                ends.as_mut_ptr(),
                pcs.as_mut_ptr(),
                init_vals.as_mut_ptr(),
                steps.as_mut_ptr(),
                count as i32,
            ))
        }
    }

    fn native_register_constant_mmio_models(
        &mut self,
        mut starts: Vec<u64>,
        mut ends: Vec<u64>,
        mut pcs: Vec<u32>,
        mut vals: Vec<u32>,
    ) -> PyResult<uc_err> {
        let count = starts.len();
        assert!(ends.len() == count && pcs.len() == count && vals.len() == count);
        unsafe {
            Ok(fuzzware::register_constant_mmio_models(
                self.uc_ptr(),
                starts.as_mut_ptr(),
                ends.as_mut_ptr(),
                pcs.as_mut_ptr(),
                vals.as_mut_ptr(),
                count as i32,
            ))
        }
    }

    fn native_register_bitextract_mmio_models(
        &mut self,
        mut starts: Vec<u64>,
        mut ends: Vec<u64>,
        mut pcs: Vec<u32>,
        mut byte_sizes: Vec<u8>,
        mut left_shifts: Vec<u8>,
        mut masks: Vec<u32>,
    ) -> PyResult<uc_err> {
        let count = starts.len();
        assert!(
            ends.len() == count
                && pcs.len() == count
                && byte_sizes.len() == count
                && left_shifts.len() == count
                && masks.len() == count
        );
        unsafe {
            Ok(fuzzware::register_bitextract_mmio_models(
                self.uc_ptr(),
                starts.as_mut_ptr(),
                ends.as_mut_ptr(),
                pcs.as_mut_ptr(),
                byte_sizes.as_mut_ptr(),
                left_shifts.as_mut_ptr(),
                masks.as_mut_ptr(),
                count as i32,
            ))
        }
    }

    fn native_register_value_set_mmio_models(
        &mut self,
        mut starts: Vec<u64>,
        mut ends: Vec<u64>,
        mut pcs: Vec<u32>,
        mut value_sets: Vec<Vec<u32>>,
    ) -> PyResult<uc_err> {
        let count = starts.len();
        assert!(ends.len() == count && pcs.len() == count && value_sets.len() == count);

        let mut value_nums: Vec<_> = value_sets.iter().map(|x| x.len() as u32).collect();
        let mut value_lists: Vec<_> = value_sets.iter_mut().map(|x| x.as_mut_ptr()).collect();

        unsafe {
            Ok(fuzzware::register_value_set_mmio_models(
                self.uc_ptr(),
                starts.as_mut_ptr(),
                ends.as_mut_ptr(),
                pcs.as_mut_ptr(),
                value_nums.as_mut_ptr(),
                value_lists.as_mut_ptr(),
                count as i32,
            ))
        }
    }

    fn native_set_ignored_mmio_addresses(
        &mut self,
        mut addrs: Vec<u64>,
        mut pcs: Vec<u32>,
    ) -> PyResult<uc_err> {
        let count = addrs.len();
        assert!(addrs.len() == pcs.len());
        unsafe {
            Ok(fuzzware::set_ignored_mmio_addresses(
                addrs.as_mut_ptr(),
                pcs.as_mut_ptr(),
                count as i32,
            ))
        }
    }

    fn native_init_nvic(
        &mut self,
        vtor: u32,
        num_irq: u32,
        interrupt_limit: u32,
        mut disabled_interrupts: Vec<u32>,
    ) -> PyResult<uc_err> {
        eprintln!(
            "Uc.native_init_nvic({vtor:#x},{num_irq},{interrupt_limit},{disabled_interrupts:x?})"
        );
        let result = unsafe {
            fuzzware::init_nvic(
                self.uc_ptr(),
                vtor,
                num_irq,
                interrupt_limit,
                disabled_interrupts.len() as u32,
                disabled_interrupts.as_mut_ptr(),
            )
        };
        Ok(result)
    }

    fn native_init_tracing(
        &mut self,
        mut bbl_set_trace_path: Option<Vec<u8>>,
        mut bbl_hash_path: Option<Vec<u8>>,
        mut mmio_set_trace_path: Option<Vec<u8>>,
        mmio_ranges: Vec<(u64, u64)>,
    ) -> PyResult<uc_err> {
        eprintln!(
            r#"Uc.native_init_tracing("{}", "{}", "{}", {mmio_ranges:0x?})"#,
            display_path(&bbl_set_trace_path),
            display_path(&bbl_hash_path),
            display_path(&mmio_set_trace_path),
        );

        let mut starts: Vec<u64> = mmio_ranges.iter().map(|(s, _)| *s).collect();
        let mut ends: Vec<u64> = mmio_ranges.iter().map(|(_, e)| *e).collect();

        let result = unsafe {
            fuzzware::init_tracing(
                self.uc_ptr(),
                get_path_ptr(&mut bbl_set_trace_path),
                get_path_ptr(&mut bbl_hash_path),
                get_path_ptr(&mut mmio_set_trace_path),
                mmio_ranges.len(),
                starts.as_mut_ptr(),
                ends.as_mut_ptr(),
            )
        };
        Ok(result)
    }

    fn native_emulate(
        &self,
        fuzz_file_path: Vec<u8>,
        mut prefix_input_file_path: Option<Vec<u8>>,
    ) -> PyResult<uc_err> {
        eprintln!(
            "Uc.native_emulate(\"{}\", \"{}\")",
            fuzz_file_path.escape_ascii(),
            display_path(&prefix_input_file_path)
        );
        let mut fuzz_file_path = Some(fuzz_file_path);
        let result = unsafe {
            fuzzware::emulate(
                self.uc_ptr(),
                get_path_ptr(&mut fuzz_file_path),
                get_path_ptr(&mut prefix_input_file_path),
            )
        };
        Ok(result)
    }

    fn add_timer<'py>(
        &mut self,
        py: Python<'py>,
        reload_value: u64,
        callback: Option<PyObject>,
        isr_number: u64,
    ) -> PyResult<u32> {
        eprintln!(
            "Uc.add_timer({reload_value}, {:p}, {isr_number})",
            callback.map_or(std::ptr::null(), |x| x.as_ref(py).as_ptr())
        );
        Ok(0)
    }
}

fn get_path_ptr(path: &mut Option<Vec<u8>>) -> *mut i8 {
    match path.as_mut() {
        Some(path) => {
            path.push(0);
            path.as_mut_ptr().cast()
        }
        None => std::ptr::null_mut(),
    }
}

fn display_path<'a>(path: &'a Option<Vec<u8>>) -> impl std::fmt::Display + 'a {
    static EMPTY: Vec<u8> = Vec::new();
    path.as_ref().unwrap_or(&EMPTY).escape_ascii()
}

#[derive(Clone)]
pub struct PythonHook {
    uc: *mut pyo3::ffi::PyObject,
    id: usize,
}

impl PythonHook {
    fn do_call<F>(&self, handle_call: F)
    where
        for<'a> F: FnOnce(&'a PyAny, Py<Uc>, Option<&PyAny>) -> PyResult<&'a PyAny>,
    {
        use pyo3::conversion::FromPyPointer;

        Python::with_gil(|py| {
            let uc: Py<Uc> =
                unsafe { PyAny::from_borrowed_ptr_or_panic(py, self.uc) }.extract().unwrap();
            let uc_ref = uc.clone();

            let (callback, user_data) = &unsafe { &*uc.borrow(py).ctx.get() }.py_callbacks[self.id];

            let result = (handle_call)(
                callback.as_ref(py),
                uc_ref,
                user_data.as_ref().map(|x| x.as_ref(py)),
            );
            if let Err(e) = result {
                e.print(py);
                panic!("Python Error");
            }
        });
    }
}

impl icicle_vm::cpu::Hook for PythonHook {
    fn call(&mut self, _cpu: &mut Cpu, pc: u64) {
        self.do_call(|callback, uc, user_data| callback.call1((uc, pc, 0, user_data)))
    }

    fn as_any(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

impl WriteHook for PythonHook {
    fn write(&mut self, _mem: &mut icicle_vm::cpu::Mmu, addr: u64, value: &[u8]) {
        self.do_call(|callback, uc, user_data| {
            let mtype = fuzzware::uc_mem_type::UC_MEM_WRITE;
            callback.call1((uc, mtype, addr, value.len(), get_u64(value), user_data))
        })
    }
}

impl ReadHook for PythonHook {
    fn read(&mut self, _mem: &mut icicle_vm::cpu::Mmu, addr: u64, size: u8) {
        self.do_call(|callback, uc, user_data| {
            let mtype = fuzzware::uc_mem_type::UC_MEM_READ;
            callback.call1((uc, mtype, addr, size as usize, 0, user_data))
        })
    }
}

impl ReadAfterHook for PythonHook {
    fn read(&mut self, _mem: &mut icicle_vm::cpu::Mmu, addr: u64, value: &[u8]) {
        self.do_call(|callback, uc, user_data| {
            let mtype = fuzzware::uc_mem_type::UC_MEM_READ_AFTER;
            callback.call1((uc, mtype, addr, value.len(), get_u64(value), user_data))
        })
    }
}

impl unicorn_api::ExceptionHook for PythonHook {
    fn handle_exception(&mut self, _addr: u64, _kind: fuzzware::uc_mem_type::Type) -> bool {
        todo!()
    }
}

static PY_EXIT_HOOK: Lazy<std::sync::Mutex<Option<PyObject>>> =
    Lazy::new(|| std::sync::Mutex::default());

type ExitHookNonNull = unsafe extern "C" fn(i32, i32);

extern "C" fn call_python_exit_hook(status: i32, kill_signal: i32) {
    Python::with_gil(|py| {
        let guard = PY_EXIT_HOOK.lock().unwrap();
        if let Some(hook) = guard.as_ref() {
            if let Err(e) = hook.call1(py, (status, kill_signal)) {
                e.print(py);
                panic!("Python Error");
            }
        }
    })
}

#[pyfunction]
fn get_latest_mmio_fuzz_access_index() -> PyResult<u32> {
    Ok(unsafe { fuzzware::get_latest_mmio_fuzz_access_index() })
}

#[pyfunction]
fn get_latest_mmio_fuzz_access_size() -> PyResult<u32> {
    Ok(unsafe { fuzzware::get_latest_mmio_fuzz_access_size() })
}

#[pyfunction]
fn fuzz_remaining() -> PyResult<u32> {
    Ok(unsafe { fuzzware::fuzz_remaining() })
}

#[pyfunction]
fn fuzz_consumed() -> PyResult<u32> {
    Ok(unsafe { fuzzware::fuzz_consumed() })
}

#[pymodule]
fn icicle(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Uc>()?;
    m.add_function(wrap_pyfunction!(get_latest_mmio_fuzz_access_index, m)?)?;
    m.add_function(wrap_pyfunction!(get_latest_mmio_fuzz_access_size, m)?)?;
    m.add_function(wrap_pyfunction!(fuzz_remaining, m)?)?;
    m.add_function(wrap_pyfunction!(fuzz_consumed, m)?)?;
    Ok(())
}
