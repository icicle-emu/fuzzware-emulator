use icicle_vm::{
    cpu::lifter::{BlockState, InstructionSource, PcodeOpInjector},
    Vm,
};
use pcode::Op;

pub(crate) const EXCP_SWI: u32 = 2;

use crate::{fuzzware::uc_arm_reg::*, Context};

pub(crate) struct SpecialRegs {
    pub ng: pcode::VarNode,
    pub zr: pcode::VarNode,
    pub cy: pcode::VarNode,
    pub ov: pcode::VarNode,
    pub xpsr: pcode::VarNode,
}

impl SpecialRegs {
    pub fn get(vm: &mut Vm) -> Self {
        Self {
            ng: vm.cpu.arch.sleigh.get_reg("NG").unwrap().var,
            zr: vm.cpu.arch.sleigh.get_reg("ZR").unwrap().var,
            cy: vm.cpu.arch.sleigh.get_reg("CY").unwrap().var,
            ov: vm.cpu.arch.sleigh.get_reg("OV").unwrap().var,
            xpsr: vm.cpu.arch.sleigh.get_reg("xpsr").unwrap().var,
        }
    }
}

const XPSR_NZCV_MASK: u32 = 0xf000_0000;

pub(crate) fn read_xpsr(ctx: &mut Context) -> u32 {
    let mut xpsr = ctx.vm.cpu.read_reg::<u32>(ctx.regs.xpsr) & !crate::arm::XPSR_NZCV_MASK;
    xpsr |= (ctx.vm.cpu.read_reg::<u8>(ctx.regs.ng) as u32) << 31;
    xpsr |= (ctx.vm.cpu.read_reg::<u8>(ctx.regs.zr) as u32) << 30;
    xpsr |= (ctx.vm.cpu.read_reg::<u8>(ctx.regs.cy) as u32) << 29;
    xpsr |= (ctx.vm.cpu.read_reg::<u8>(ctx.regs.ov) as u32) << 28;
    xpsr
}

pub(crate) fn write_xpsr(ctx: &mut Context, xpsr: u32) {
    ctx.vm.cpu.write_reg::<u8>(ctx.regs.ng, ((xpsr >> 31) & 0b1) as u8);
    ctx.vm.cpu.write_reg::<u8>(ctx.regs.zr, ((xpsr >> 30) & 0b1) as u8);
    ctx.vm.cpu.write_reg::<u8>(ctx.regs.cy, ((xpsr >> 29) & 0b1) as u8);
    ctx.vm.cpu.write_reg::<u8>(ctx.regs.ov, ((xpsr >> 28) & 0b1) as u8);
    ctx.vm.cpu.write_reg::<u32>(ctx.regs.xpsr, xpsr);
}

/// Most of this should probably be implemented as part of the SLEIGH specification instead.
pub(crate) fn add_arm_extras(vm: &mut Vm) {
    const CPSR_IRQ_MASK_BIT: u32 = 1 << 7;
    const CPSR_FIQ_MASK_BIT: u32 = 1 << 6;

    // Add missing registers.
    let xpsr_reg = vm.cpu.arch.sleigh.add_custom_reg("xpsr", 4).unwrap();
    let other_sp_reg = vm.cpu.arch.sleigh.add_custom_reg("other_sp", 4).unwrap();
    let basepri_reg = vm.cpu.arch.sleigh.add_custom_reg("basepri", 4).unwrap();
    let primask_reg = vm.cpu.arch.sleigh.add_custom_reg("primask", 4).unwrap();

    override_op(
        vm,
        "getCurrentExceptionNumber",
        move |_: &dyn InstructionSource, _, _, output: pcode::VarNode, b: &mut BlockState| {
            b.pcode.push((output, Op::IntAnd, (xpsr_reg, 0x1ff_u32)));
            false
        },
    );

    override_op(
        vm,
        "enableIRQinterrupts",
        move |_: &dyn InstructionSource, _, _, _, b: &mut BlockState| {
            b.pcode.push((primask_reg, Op::IntAnd, (primask_reg, !CPSR_IRQ_MASK_BIT)));
            false
        },
    );

    override_op(
        vm,
        "disableIRQinterrupts",
        move |_: &dyn InstructionSource, _, _, _, b: &mut BlockState| {
            b.pcode.push((primask_reg, Op::IntOr, (primask_reg, CPSR_IRQ_MASK_BIT)));
            false
        },
    );

    override_op(
        vm,
        "enableFIQinterrupts",
        move |_: &dyn InstructionSource, _, _, _, b: &mut BlockState| {
            b.pcode.push((primask_reg, Op::IntAnd, (primask_reg, !CPSR_FIQ_MASK_BIT)));
            false
        },
    );

    override_op(
        vm,
        "disableFIQinterrupts",
        move |_: &dyn InstructionSource, _, _, _, b: &mut BlockState| {
            b.pcode.push((primask_reg, Op::IntOr, (primask_reg, CPSR_FIQ_MASK_BIT)));
            false
        },
    );

    override_op(
        vm,
        "isIRQinterruptsEnabled",
        move |_: &dyn InstructionSource, _, _, output, b: &mut BlockState| {
            let shift = 31 - CPSR_IRQ_MASK_BIT.leading_zeros();
            b.pcode.push((output, Op::IntRight, (primask_reg, shift)));
            // Even though the p-code operation is called "isIRQinterruptsEnabled" it is intended to
            // returns the value of `PRIMASK` directly (which is 0 when interrupts are enabled, and
            // 1 when they are enabled).
            // b.pcode.push((output, Op::IntNot, output));
            b.pcode.push((output, Op::IntAnd, (output, 1)));
            false
        },
    );

    override_op(
        vm,
        "getBasePriority",
        move |_: &dyn InstructionSource, _, _, output: pcode::VarNode, b: &mut BlockState| {
            b.pcode.push((output, Op::IntAnd, (basepri_reg, 0xff_u32)));
            false
        },
    );

    override_op(
        vm,
        "setBasePriority",
        move |_: &dyn InstructionSource, _, inputs: pcode::Inputs, _, b: &mut BlockState| {
            let val = inputs.first();
            b.pcode.push((basepri_reg, Op::IntAnd, (val, 0xff_u32)));
            false
        },
    );

    // Control registers. controls current mode of the stack and whether thread mode should be
    // privileged.
    //
    // Bit 0: Execution privilege in thread mode:
    //  - 0: thread mode is unprivilege
    //  - 1: thread mode is privilege
    //
    // Bit 1:
    //  - 0: thread mode
    //  - 1: main-stack mode
    let control = vm.cpu.arch.sleigh.add_custom_reg("spsel", 4).unwrap();
    // Cached copy of spsel bit 1
    let current_sp_mode_is_psp =
        vm.cpu.arch.sleigh.add_custom_reg("curr_sp_mode_is_psp", 4).unwrap();

    override_op(
        vm,
        "isCurrentModePrivileged",
        move |_: &dyn InstructionSource, _, _, output: pcode::VarNode, b: &mut BlockState| {
            // Assume always true to match unicorn behavior.
            // Note: should be equal to `control & 1` in thread mode and `1` in main stack mode.
            b.pcode.push((output, Op::Copy, pcode::Value::Const(1, output.size)));
            false
        },
    );

    override_op(
        vm,
        "isThreadModePrivileged",
        move |_: &dyn InstructionSource, _, _, output: pcode::VarNode, b: &mut BlockState| {
            b.pcode.push((output, Op::IntAnd, (control.truncate(1), 0b1_u8)));
            false
        },
    );

    override_op(
        vm,
        "setThreadModePrivileged",
        move |_: &dyn InstructionSource, _, inputs: pcode::Inputs, _, b: &mut BlockState| {
            let is_privileged = inputs.first();
            b.pcode.push((control, Op::IntAnd, (control, !0b1_u32)));
            b.pcode.push((control.truncate(1), Op::IntOr, (control.truncate(1), is_privileged)));
            false
        },
    );

    override_op(
        vm,
        "isThreadMode",
        move |_: &dyn InstructionSource, _, _, output: pcode::VarNode, b: &mut BlockState| {
            b.pcode.push((output, Op::IntEqual, (current_sp_mode_is_psp, 1_u32)));
            false
        },
    );

    let sp_reg = vm.cpu.arch.reg_sp;
    override_op(
        vm,
        "getMainStackPointer",
        move |_: &dyn InstructionSource, _, _, output, b: &mut BlockState| {
            b.pcode.select(output, current_sp_mode_is_psp, other_sp_reg, sp_reg);
            false
        },
    );
    override_op(
        vm,
        "setMainStackPointer",
        move |_: &dyn InstructionSource, _, inputs: pcode::Inputs, _, b: &mut BlockState| {
            let val = inputs.first();
            b.pcode.select(sp_reg, current_sp_mode_is_psp, sp_reg, val);
            b.pcode.select(other_sp_reg, current_sp_mode_is_psp, val, other_sp_reg);
            false
        },
    );
    override_op(
        vm,
        "getProcessStackPointer",
        move |_: &dyn InstructionSource, _, _, output, b: &mut BlockState| {
            b.pcode.select(output, current_sp_mode_is_psp, sp_reg, other_sp_reg);
            false
        },
    );
    override_op(
        vm,
        "setProcessStackPointer",
        move |_: &dyn InstructionSource, _, inputs: pcode::Inputs, _, b: &mut BlockState| {
            let val = inputs.first();
            b.pcode.select(sp_reg, current_sp_mode_is_psp, val, sp_reg);
            b.pcode.select(other_sp_reg, current_sp_mode_is_psp, other_sp_reg, val);
            false
        },
    );
    override_op(
        vm,
        "setStackMode",
        move |_: &dyn InstructionSource, _, inputs: pcode::Inputs, _, b: &mut BlockState| {
            let mode = b.pcode.alloc_tmp(4);
            b.pcode.push((mode, Op::ZeroExtend, inputs.first()));

            // Switch stacks if required.
            let mode_changed = b.pcode.alloc_tmp(1);
            b.pcode.push((mode_changed, Op::IntEqual, (current_sp_mode_is_psp, mode)));
            let new_sp = b.pcode.alloc_tmp(4);
            b.pcode.select(new_sp, mode_changed, other_sp_reg, sp_reg);
            b.pcode.select(other_sp_reg, mode_changed, sp_reg, other_sp_reg);
            b.pcode.push((sp_reg, Op::Copy, new_sp));

            // Update registers that keep track of the current stack mode.
            b.pcode.push((current_sp_mode_is_psp, Op::Copy, mode));
            b.pcode.push((mode, Op::IntLeft, (mode, 1_u32)));
            b.pcode.push((control, Op::IntAnd, (control, !0b10_u32)));
            b.pcode.push((control, Op::IntOr, (control, mode)));
            false
        },
    );
    override_op(
        vm,
        "isUsingMainStack",
        move |_: &dyn InstructionSource, _, _, output: pcode::VarNode, b: &mut BlockState| {
            b.pcode.push((output, Op::IntEqual, (current_sp_mode_is_psp, 0_u32)));
            false
        },
    );
}

fn override_op(vm: &mut Vm, name: &str, injector: impl PcodeOpInjector + Sized + 'static) {
    let idx = vm.cpu.arch.sleigh.get_userop(name).unwrap();
    vm.lifter.op_injectors.insert(idx, Box::new(injector));
}

/// Returns a mapping from Unicorn Register IDs to Icicle varnodes.
pub(crate) fn map_uc_to_varnodes(vm: &Vm) -> Vec<pcode::VarNode> {
    let mut vars = vec![pcode::VarNode::NONE; UC_ARM_REG_ENDING as usize];

    let mut map = |id: u32, name: &str| match vm.cpu.arch.sleigh.get_reg(name) {
        Some(reg) => vars[id as usize] = reg.var,
        None => eprintln!("{name} not found in Sleigh spec"),
    };

    // map(UC_ARM_REG_APSR, "apsr");
    // map(UC_ARM_REG_APSR_NZCV, "apsr_nzcv");
    map(UC_ARM_REG_CPSR, "cpsr");
    map(UC_ARM_REG_FPEXC, "fpexc");
    // map(UC_ARM_REG_FPINST, "fpinst");
    map(UC_ARM_REG_FPSCR, "fpscr");
    // map(UC_ARM_REG_FPSCR_NZCV, "fpscr_nzcv");
    map(UC_ARM_REG_FPSID, "fpsid");
    // map(UC_ARM_REG_ITSTATE, "itstate");
    map(UC_ARM_REG_LR, "lr");
    map(UC_ARM_REG_PC, "pc");
    map(UC_ARM_REG_SP, "sp");
    map(UC_ARM_REG_SPSR, "spsr");
    map(UC_ARM_REG_D0, "d0");
    map(UC_ARM_REG_D1, "d1");
    map(UC_ARM_REG_D2, "d2");
    map(UC_ARM_REG_D3, "d3");
    map(UC_ARM_REG_D4, "d4");
    map(UC_ARM_REG_D5, "d5");
    map(UC_ARM_REG_D6, "d6");
    map(UC_ARM_REG_D7, "d7");
    map(UC_ARM_REG_D8, "d8");
    map(UC_ARM_REG_D9, "d9");
    map(UC_ARM_REG_D10, "d10");
    map(UC_ARM_REG_D11, "d11");
    map(UC_ARM_REG_D12, "d12");
    map(UC_ARM_REG_D13, "d13");
    map(UC_ARM_REG_D14, "d14");
    map(UC_ARM_REG_D15, "d15");
    map(UC_ARM_REG_D16, "d16");
    map(UC_ARM_REG_D17, "d17");
    map(UC_ARM_REG_D18, "d18");
    map(UC_ARM_REG_D19, "d19");
    map(UC_ARM_REG_D20, "d20");
    map(UC_ARM_REG_D21, "d21");
    map(UC_ARM_REG_D22, "d22");
    map(UC_ARM_REG_D23, "d23");
    map(UC_ARM_REG_D24, "d24");
    map(UC_ARM_REG_D25, "d25");
    map(UC_ARM_REG_D26, "d26");
    map(UC_ARM_REG_D27, "d27");
    map(UC_ARM_REG_D28, "d28");
    map(UC_ARM_REG_D29, "d29");
    map(UC_ARM_REG_D30, "d30");
    map(UC_ARM_REG_D31, "d31");
    // map(UC_ARM_REG_FPINST2, "fpinst2");
    map(UC_ARM_REG_MVFR0, "mvfr0");
    map(UC_ARM_REG_MVFR1, "mvfr1");
    // map(UC_ARM_REG_MVFR2, "mvfr2");
    map(UC_ARM_REG_Q0, "q0");
    map(UC_ARM_REG_Q1, "q1");
    map(UC_ARM_REG_Q2, "q2");
    map(UC_ARM_REG_Q3, "q3");
    map(UC_ARM_REG_Q4, "q4");
    map(UC_ARM_REG_Q5, "q5");
    map(UC_ARM_REG_Q6, "q6");
    map(UC_ARM_REG_Q7, "q7");
    map(UC_ARM_REG_Q8, "q8");
    map(UC_ARM_REG_Q9, "q9");
    map(UC_ARM_REG_Q10, "q10");
    map(UC_ARM_REG_Q11, "q11");
    map(UC_ARM_REG_Q12, "q12");
    map(UC_ARM_REG_Q13, "q13");
    map(UC_ARM_REG_Q14, "q14");
    map(UC_ARM_REG_Q15, "q15");
    map(UC_ARM_REG_R0, "r0");
    map(UC_ARM_REG_R1, "r1");
    map(UC_ARM_REG_R2, "r2");
    map(UC_ARM_REG_R3, "r3");
    map(UC_ARM_REG_R4, "r4");
    map(UC_ARM_REG_R5, "r5");
    map(UC_ARM_REG_R6, "r6");
    map(UC_ARM_REG_R7, "r7");
    map(UC_ARM_REG_R8, "r8");
    map(UC_ARM_REG_R9, "r9");
    map(UC_ARM_REG_R10, "r10");
    map(UC_ARM_REG_R11, "r11");
    map(UC_ARM_REG_R12, "r12");
    map(UC_ARM_REG_S0, "s0");
    map(UC_ARM_REG_S1, "s1");
    map(UC_ARM_REG_S2, "s2");
    map(UC_ARM_REG_S3, "s3");
    map(UC_ARM_REG_S4, "s4");
    map(UC_ARM_REG_S5, "s5");
    map(UC_ARM_REG_S6, "s6");
    map(UC_ARM_REG_S7, "s7");
    map(UC_ARM_REG_S8, "s8");
    map(UC_ARM_REG_S9, "s9");
    map(UC_ARM_REG_S10, "s10");
    map(UC_ARM_REG_S11, "s11");
    map(UC_ARM_REG_S12, "s12");
    map(UC_ARM_REG_S13, "s13");
    map(UC_ARM_REG_S14, "s14");
    map(UC_ARM_REG_S15, "s15");
    map(UC_ARM_REG_S16, "s16");
    map(UC_ARM_REG_S17, "s17");
    map(UC_ARM_REG_S18, "s18");
    map(UC_ARM_REG_S19, "s19");
    map(UC_ARM_REG_S20, "s20");
    map(UC_ARM_REG_S21, "s21");
    map(UC_ARM_REG_S22, "s22");
    map(UC_ARM_REG_S23, "s23");
    map(UC_ARM_REG_S24, "s24");
    map(UC_ARM_REG_S25, "s25");
    map(UC_ARM_REG_S26, "s26");
    map(UC_ARM_REG_S27, "s27");
    map(UC_ARM_REG_S28, "s28");
    map(UC_ARM_REG_S29, "s29");
    map(UC_ARM_REG_S30, "s30");
    map(UC_ARM_REG_S31, "s31");
    // map(UC_ARM_REG_C1_C0_2, "c1_c0_2");
    // map(UC_ARM_REG_C13_C0_2, "c13_c0_2");
    // map(UC_ARM_REG_C13_C0_3, "c13_c0_3");
    // map(UC_ARM_REG_IPSR, "ipsr");
    // map(UC_ARM_REG_MSP, "msp");
    // map(UC_ARM_REG_PSP, "psp");
    // map(UC_ARM_REG_CONTROL, "control");

    // Registers missing from SLEIGH spec
    map(UC_ARM_REG_XPSR, "xpsr");
    map(UC_ARM_REG_OTHER_SP, "other_sp");
    map(UC_ARM_REG_CURR_SP_MODE_IS_PSP, "curr_sp_mode_is_psp");
    map(UC_ARM_REG_SPSEL, "spsel");
    map(UC_ARM_REG_BASEPRI, "basepri");
    map(UC_ARM_REG_PRIMASK, "primask");

    // These are aliases to other registers.
    // map(UC_ARM_REG_R13, "sp");
    // map(UC_ARM_REG_R14, "lr");
    // map(UC_ARM_REG_R15, "pc");
    // map(UC_ARM_REG_SB, "r9");
    // map(UC_ARM_REG_SL, "r10");
    // map(UC_ARM_REG_FP, "r11");
    // map(UC_ARM_REG_IP, "r12");

    vars
}
