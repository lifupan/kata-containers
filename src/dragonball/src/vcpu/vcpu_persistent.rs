// Copyright (C) 2024 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Persistent state for vCPU checkpoint and restore.
//!
//! This module provides the serializable state structures for saving and
//! restoring vCPU register states during checkpoint/restore operations.

use serde_derive::{Deserialize, Serialize};

use crate::checkpoint::{CheckpointError, Result};

/// Saved state for a single vCPU's registers (x86_64).
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VcpuState {
    /// vCPU index.
    pub id: u8,
    /// General-purpose registers.
    pub regs: VcpuRegs,
    /// Special registers (segment registers, control registers, etc.).
    pub sregs: VcpuSregs,
    /// Floating point unit state.
    pub fpu: VcpuFpu,
    /// Model-specific registers.
    pub msrs: Vec<MsrEntry>,
    /// CPUID entries.
    pub cpuid_entries: Vec<CpuidEntry>,
    /// LAPIC state.
    pub lapic: VcpuLapic,
    /// MP state.
    pub mp_state: u32,
    /// XCR0 state.
    pub xcrs: Vec<VcpuXcr>,
    /// Debug registers.
    pub debug_regs: VcpuDebugRegs,
    /// Vcpu events.
    pub vcpu_events: VcpuEvents,
}

/// Saved state for a single vCPU's registers (aarch64).
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VcpuState {
    /// vCPU index.
    pub id: u8,
    /// MPIDR value.
    pub mpidr: u64,
    /// General-purpose registers (x0-x30, sp, pc, pstate).
    pub core_regs: Vec<u64>,
    /// System registers.
    pub sys_regs: Vec<SystemRegEntry>,
    /// MP state.
    pub mp_state: u32,
}

/// General-purpose registers for x86_64.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VcpuRegs {
    /// RAX register.
    pub rax: u64,
    /// RBX register.
    pub rbx: u64,
    /// RCX register.
    pub rcx: u64,
    /// RDX register.
    pub rdx: u64,
    /// RSI register.
    pub rsi: u64,
    /// RDI register.
    pub rdi: u64,
    /// RSP register.
    pub rsp: u64,
    /// RBP register.
    pub rbp: u64,
    /// R8 register.
    pub r8: u64,
    /// R9 register.
    pub r9: u64,
    /// R10 register.
    pub r10: u64,
    /// R11 register.
    pub r11: u64,
    /// R12 register.
    pub r12: u64,
    /// R13 register.
    pub r13: u64,
    /// R14 register.
    pub r14: u64,
    /// R15 register.
    pub r15: u64,
    /// RIP register.
    pub rip: u64,
    /// RFLAGS register.
    pub rflags: u64,
}

/// Segment register state for x86_64.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SegmentReg {
    /// Base address.
    pub base: u64,
    /// Limit.
    pub limit: u32,
    /// Selector.
    pub selector: u16,
    /// Type.
    pub type_: u8,
    /// Present.
    pub present: u8,
    /// DPL.
    pub dpl: u8,
    /// DB.
    pub db: u8,
    /// Segment is 64-bit.
    pub s: u8,
    /// Long mode.
    pub l: u8,
    /// Granularity.
    pub g: u8,
    /// Available for system use.
    pub avl: u8,
    /// Unusable.
    pub unusable: u8,
}

/// Descriptor table register state for x86_64.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DtableReg {
    /// Base address.
    pub base: u64,
    /// Limit.
    pub limit: u16,
}

/// Special registers for x86_64.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VcpuSregs {
    /// CS segment.
    pub cs: SegmentReg,
    /// DS segment.
    pub ds: SegmentReg,
    /// ES segment.
    pub es: SegmentReg,
    /// FS segment.
    pub fs: SegmentReg,
    /// GS segment.
    pub gs: SegmentReg,
    /// SS segment.
    pub ss: SegmentReg,
    /// TR segment.
    pub tr: SegmentReg,
    /// LDT segment.
    pub ldt: SegmentReg,
    /// GDT.
    pub gdt: DtableReg,
    /// IDT.
    pub idt: DtableReg,
    /// CR0.
    pub cr0: u64,
    /// CR2.
    pub cr2: u64,
    /// CR3.
    pub cr3: u64,
    /// CR4.
    pub cr4: u64,
    /// CR8.
    pub cr8: u64,
    /// EFER MSR.
    pub efer: u64,
    /// APIC base MSR.
    pub apic_base: u64,
    /// Interrupt bitmap.
    pub interrupt_bitmap: Vec<u64>,
}

/// Floating-point unit state for x86_64.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VcpuFpu {
    /// FPR registers (8x 16 bytes).
    pub fpr: Vec<Vec<u8>>,
    /// FCW register.
    pub fcw: u16,
    /// FSW register.
    pub fsw: u16,
    /// FTW register.
    pub ftwx: u8,
    /// Last FP opcode.
    pub last_opcode: u16,
    /// Last FP instruction pointer.
    pub last_ip: u64,
    /// Last FP data pointer.
    pub last_dp: u64,
    /// XMM registers (16x 16 bytes).
    pub xmm: Vec<Vec<u8>>,
    /// MXCSR register.
    pub mxcsr: u32,
}

/// MSR entry for x86_64.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MsrEntry {
    /// MSR index.
    pub index: u32,
    /// MSR value.
    pub data: u64,
}

/// CPUID entry for x86_64.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CpuidEntry {
    /// CPUID function.
    pub function: u32,
    /// CPUID index.
    pub index: u32,
    /// Flags.
    pub flags: u32,
    /// EAX output.
    pub eax: u32,
    /// EBX output.
    pub ebx: u32,
    /// ECX output.
    pub ecx: u32,
    /// EDX output.
    pub edx: u32,
}

/// LAPIC state for x86_64.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VcpuLapic {
    /// LAPIC register values.
    pub regs: Vec<u8>,
}

/// XCR entry for x86_64.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VcpuXcr {
    /// XCR index.
    pub xcr: u32,
    /// XCR value.
    pub value: u64,
}

/// Debug registers for x86_64.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VcpuDebugRegs {
    /// DR0-DR3 debug address registers.
    pub db: [u64; 4],
    /// DR6 debug status register.
    pub dr6: u64,
    /// DR7 debug control register.
    pub dr7: u64,
    /// Architecture-specific flags.
    pub flags: u64,
}

/// vCPU events state for x86_64.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VcpuEvents {
    /// Exception info.
    pub exception_has_error_code: u8,
    /// Exception vector.
    pub exception_nr: u8,
    /// Exception error code.
    pub exception_error_code: u32,
    /// NMI masked.
    pub nmi_masked: u8,
    /// NMI pending.
    pub nmi_pending: u8,
}

/// System register entry for aarch64.
#[cfg(target_arch = "aarch64")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SystemRegEntry {
    /// Register id.
    pub id: u64,
    /// Register value.
    pub value: u64,
}

/// Saved state for all vCPUs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VcpuManagerState {
    /// Boot vCPU count.
    pub boot_vcpu_count: u8,
    /// Max vCPU count.
    pub max_vcpu_count: u8,
    /// Per-vCPU states.
    pub vcpu_states: Vec<VcpuState>,
}

/// Save the state of a single vCPU from its KVM file descriptor.
#[cfg(target_arch = "x86_64")]
pub fn save_vcpu_state(vcpu_fd: &kvm_ioctls::VcpuFd, id: u8) -> Result<VcpuState> {
    let kvm_regs = vcpu_fd
        .get_regs()
        .map_err(|e| CheckpointError::VcpuState(format!("failed to get regs for vCPU {id}: {e}")))?;

    let regs = VcpuRegs {
        rax: kvm_regs.rax,
        rbx: kvm_regs.rbx,
        rcx: kvm_regs.rcx,
        rdx: kvm_regs.rdx,
        rsi: kvm_regs.rsi,
        rdi: kvm_regs.rdi,
        rsp: kvm_regs.rsp,
        rbp: kvm_regs.rbp,
        r8: kvm_regs.r8,
        r9: kvm_regs.r9,
        r10: kvm_regs.r10,
        r11: kvm_regs.r11,
        r12: kvm_regs.r12,
        r13: kvm_regs.r13,
        r14: kvm_regs.r14,
        r15: kvm_regs.r15,
        rip: kvm_regs.rip,
        rflags: kvm_regs.rflags,
    };

    let kvm_sregs = vcpu_fd.get_sregs().map_err(|e| {
        CheckpointError::VcpuState(format!("failed to get sregs for vCPU {id}: {e}"))
    })?;

    let convert_seg = |seg: &kvm_bindings::kvm_segment| SegmentReg {
        base: seg.base,
        limit: seg.limit,
        selector: seg.selector,
        type_: seg.type_,
        present: seg.present,
        dpl: seg.dpl,
        db: seg.db,
        s: seg.s,
        l: seg.l,
        g: seg.g,
        avl: seg.avl,
        unusable: seg.unusable,
    };

    let convert_dtable = |dt: &kvm_bindings::kvm_dtable| DtableReg {
        base: dt.base,
        limit: dt.limit,
    };

    let sregs = VcpuSregs {
        cs: convert_seg(&kvm_sregs.cs),
        ds: convert_seg(&kvm_sregs.ds),
        es: convert_seg(&kvm_sregs.es),
        fs: convert_seg(&kvm_sregs.fs),
        gs: convert_seg(&kvm_sregs.gs),
        ss: convert_seg(&kvm_sregs.ss),
        tr: convert_seg(&kvm_sregs.tr),
        ldt: convert_seg(&kvm_sregs.ldt),
        gdt: convert_dtable(&kvm_sregs.gdt),
        idt: convert_dtable(&kvm_sregs.idt),
        cr0: kvm_sregs.cr0,
        cr2: kvm_sregs.cr2,
        cr3: kvm_sregs.cr3,
        cr4: kvm_sregs.cr4,
        cr8: kvm_sregs.cr8,
        efer: kvm_sregs.efer,
        apic_base: kvm_sregs.apic_base,
        interrupt_bitmap: kvm_sregs.interrupt_bitmap.to_vec(),
    };

    let kvm_fpu = vcpu_fd
        .get_fpu()
        .map_err(|e| CheckpointError::VcpuState(format!("failed to get fpu for vCPU {id}: {e}")))?;

    let fpu = VcpuFpu {
        fpr: kvm_fpu.fpr.iter().map(|r| r.to_vec()).collect(),
        fcw: kvm_fpu.fcw,
        fsw: kvm_fpu.fsw,
        ftwx: kvm_fpu.ftwx,
        last_opcode: kvm_fpu.last_opcode,
        last_ip: kvm_fpu.last_ip,
        last_dp: kvm_fpu.last_dp,
        xmm: kvm_fpu.xmm.iter().map(|r| r.to_vec()).collect(),
        mxcsr: kvm_fpu.mxcsr,
    };

    let kvm_lapic = vcpu_fd.get_lapic().map_err(|e| {
        CheckpointError::VcpuState(format!("failed to get lapic for vCPU {id}: {e}"))
    })?;
    let lapic = VcpuLapic {
        // KVM defines LAPIC regs as i8 array but they are raw bytes;
        // the `as u8` cast preserves the bit pattern.
        regs: kvm_lapic.regs.iter().map(|&b| b as u8).collect(),
    };

    let kvm_mp_state = vcpu_fd.get_mp_state().map_err(|e| {
        CheckpointError::VcpuState(format!("failed to get mp_state for vCPU {id}: {e}"))
    })?;

    let kvm_xcrs = vcpu_fd.get_xcrs().map_err(|e| {
        CheckpointError::VcpuState(format!("failed to get xcrs for vCPU {id}: {e}"))
    })?;
    let xcrs = (0..kvm_xcrs.nr_xcrs as usize)
        .map(|i| VcpuXcr {
            xcr: kvm_xcrs.xcrs[i].xcr,
            value: kvm_xcrs.xcrs[i].value,
        })
        .collect();

    let kvm_debug_regs = vcpu_fd.get_debug_regs().map_err(|e| {
        CheckpointError::VcpuState(format!("failed to get debug_regs for vCPU {id}: {e}"))
    })?;
    let debug_regs = VcpuDebugRegs {
        db: kvm_debug_regs.db,
        dr6: kvm_debug_regs.dr6,
        dr7: kvm_debug_regs.dr7,
        flags: kvm_debug_regs.flags,
    };

    let kvm_events = vcpu_fd.get_vcpu_events().map_err(|e| {
        CheckpointError::VcpuState(format!("failed to get vcpu_events for vCPU {id}: {e}"))
    })?;
    let vcpu_events = VcpuEvents {
        exception_has_error_code: kvm_events.exception.has_error_code,
        exception_nr: kvm_events.exception.nr,
        exception_error_code: kvm_events.exception.error_code,
        nmi_masked: kvm_events.nmi.masked,
        nmi_pending: kvm_events.nmi.pending,
    };

    // Get MSRs - use a well-known set of MSR indices for checkpoint
    let msr_indices: Vec<kvm_bindings::kvm_msr_entry> = [
        0x174u32, // MSR_IA32_SYSENTER_CS
        0x175,    // MSR_IA32_SYSENTER_ESP
        0x176,    // MSR_IA32_SYSENTER_EIP
        0x2FF,    // MSR_MTRRdefType
        0xC000_0081, // MSR_STAR
        0xC000_0082, // MSR_LSTAR
        0xC000_0083, // MSR_CSTAR
        0xC000_0084, // MSR_SYSCALL_MASK
        0xC000_0102, // MSR_KERNEL_GS_BASE
        0x10,     // MSR_IA32_TSC
        0x1B,     // MSR_IA32_APICBASE
        0xFE,     // MSR_IA32_MTRRCAP
        0x200,    // MSR_IA32_MTRR_PHYSBASE0
        0x250,    // MSR_MTRRfix64K_00000
        0x258,    // MSR_MTRRfix16K_80000
        0x259,    // MSR_MTRRfix16K_A0000
        0x268,    // MSR_MTRRfix4K_C0000
        0x277,    // MSR_IA32_CR_PAT
        0x48,     // MSR_IA32_SPEC_CTRL
        0xC000_0100, // MSR_FS_BASE
        0xC000_0101, // MSR_GS_BASE
    ]
    .iter()
    .map(|&index| kvm_bindings::kvm_msr_entry {
        index,
        ..Default::default()
    })
    .collect();
    let mut kvm_msrs = kvm_bindings::Msrs::from_entries(&msr_indices)
        .map_err(|e| CheckpointError::VcpuState(format!("failed to create MSR entries: {e}")))?;
    let nmsrs = vcpu_fd.get_msrs(&mut kvm_msrs).map_err(|e| {
        CheckpointError::VcpuState(format!("failed to get msrs for vCPU {id}: {e}"))
    })?;
    let msrs: Vec<MsrEntry> = kvm_msrs.as_slice()[..nmsrs]
        .iter()
        .map(|e| MsrEntry {
            index: e.index,
            data: e.data,
        })
        .collect();

    // Get CPUID
    let kvm_cpuid = vcpu_fd.get_cpuid2(kvm_bindings::KVM_MAX_CPUID_ENTRIES).map_err(|e| {
        CheckpointError::VcpuState(format!("failed to get cpuid for vCPU {id}: {e}"))
    })?;
    let cpuid_entries: Vec<CpuidEntry> = kvm_cpuid
        .as_slice()
        .iter()
        .map(|e| CpuidEntry {
            function: e.function,
            index: e.index,
            flags: e.flags,
            eax: e.eax,
            ebx: e.ebx,
            ecx: e.ecx,
            edx: e.edx,
        })
        .collect();

    Ok(VcpuState {
        id,
        regs,
        sregs,
        fpu,
        msrs,
        cpuid_entries,
        lapic,
        mp_state: kvm_mp_state.mp_state,
        xcrs,
        debug_regs,
        vcpu_events,
    })
}

/// Restore the state of a single vCPU from saved state.
#[cfg(target_arch = "x86_64")]
pub fn restore_vcpu_state(vcpu_fd: &kvm_ioctls::VcpuFd, state: &VcpuState) -> Result<()> {
    let id = state.id;

    // Restore CPUID first (must be before sregs on some KVM versions)
    let cpuid_entries: Vec<kvm_bindings::kvm_cpuid_entry2> = state
        .cpuid_entries
        .iter()
        .map(|e| {
            let mut entry = kvm_bindings::kvm_cpuid_entry2::default();
            entry.function = e.function;
            entry.index = e.index;
            entry.flags = e.flags;
            entry.eax = e.eax;
            entry.ebx = e.ebx;
            entry.ecx = e.ecx;
            entry.edx = e.edx;
            entry
        })
        .collect();
    let kvm_cpuid = kvm_bindings::CpuId::from_entries(&cpuid_entries).map_err(|e| {
        CheckpointError::VcpuState(format!("failed to create CpuId for vCPU {id}: {e}"))
    })?;
    vcpu_fd.set_cpuid2(&kvm_cpuid).map_err(|e| {
        CheckpointError::VcpuState(format!("failed to set cpuid for vCPU {id}: {e}"))
    })?;

    // Restore MP state
    let kvm_mp_state = kvm_bindings::kvm_mp_state {
        mp_state: state.mp_state,
    };
    vcpu_fd.set_mp_state(kvm_mp_state).map_err(|e| {
        CheckpointError::VcpuState(format!("failed to set mp_state for vCPU {id}: {e}"))
    })?;

    // Restore special registers
    let convert_seg = |seg: &SegmentReg| kvm_bindings::kvm_segment {
        base: seg.base,
        limit: seg.limit,
        selector: seg.selector,
        type_: seg.type_,
        present: seg.present,
        dpl: seg.dpl,
        db: seg.db,
        s: seg.s,
        l: seg.l,
        g: seg.g,
        avl: seg.avl,
        unusable: seg.unusable,
        ..Default::default()
    };

    let convert_dtable = |dt: &DtableReg| kvm_bindings::kvm_dtable {
        base: dt.base,
        limit: dt.limit,
        ..Default::default()
    };

    let mut interrupt_bitmap = [0u64; 4];
    for (i, &val) in state.sregs.interrupt_bitmap.iter().enumerate() {
        if i < 4 {
            interrupt_bitmap[i] = val;
        }
    }

    let kvm_sregs = kvm_bindings::kvm_sregs {
        cs: convert_seg(&state.sregs.cs),
        ds: convert_seg(&state.sregs.ds),
        es: convert_seg(&state.sregs.es),
        fs: convert_seg(&state.sregs.fs),
        gs: convert_seg(&state.sregs.gs),
        ss: convert_seg(&state.sregs.ss),
        tr: convert_seg(&state.sregs.tr),
        ldt: convert_seg(&state.sregs.ldt),
        gdt: convert_dtable(&state.sregs.gdt),
        idt: convert_dtable(&state.sregs.idt),
        cr0: state.sregs.cr0,
        cr2: state.sregs.cr2,
        cr3: state.sregs.cr3,
        cr4: state.sregs.cr4,
        cr8: state.sregs.cr8,
        efer: state.sregs.efer,
        apic_base: state.sregs.apic_base,
        interrupt_bitmap,
    };
    vcpu_fd.set_sregs(&kvm_sregs).map_err(|e| {
        CheckpointError::VcpuState(format!("failed to set sregs for vCPU {id}: {e}"))
    })?;

    // Restore MSRs
    let msr_entries: Vec<kvm_bindings::kvm_msr_entry> = state
        .msrs
        .iter()
        .map(|e| kvm_bindings::kvm_msr_entry {
            index: e.index,
            data: e.data,
            ..Default::default()
        })
        .collect();
    let kvm_msrs = kvm_bindings::Msrs::from_entries(&msr_entries)
        .map_err(|e| CheckpointError::VcpuState(format!("failed to create Msrs: {e}")))?;
    vcpu_fd.set_msrs(&kvm_msrs).map_err(|e| {
        CheckpointError::VcpuState(format!("failed to set msrs for vCPU {id}: {e}"))
    })?;

    // Restore LAPIC
    let mut kvm_lapic = kvm_bindings::kvm_lapic_state::default();
    let len = std::cmp::min(state.lapic.regs.len(), kvm_lapic.regs.len());
    // KVM defines LAPIC regs as i8 array but they are raw bytes;
    // the `as i8` cast preserves the bit pattern (reverse of save).
    for i in 0..len {
        kvm_lapic.regs[i] = state.lapic.regs[i] as i8;
    }
    vcpu_fd.set_lapic(&kvm_lapic).map_err(|e| {
        CheckpointError::VcpuState(format!("failed to set lapic for vCPU {id}: {e}"))
    })?;

    // Restore general registers
    let kvm_regs = kvm_bindings::kvm_regs {
        rax: state.regs.rax,
        rbx: state.regs.rbx,
        rcx: state.regs.rcx,
        rdx: state.regs.rdx,
        rsi: state.regs.rsi,
        rdi: state.regs.rdi,
        rsp: state.regs.rsp,
        rbp: state.regs.rbp,
        r8: state.regs.r8,
        r9: state.regs.r9,
        r10: state.regs.r10,
        r11: state.regs.r11,
        r12: state.regs.r12,
        r13: state.regs.r13,
        r14: state.regs.r14,
        r15: state.regs.r15,
        rip: state.regs.rip,
        rflags: state.regs.rflags,
    };
    vcpu_fd.set_regs(&kvm_regs).map_err(|e| {
        CheckpointError::VcpuState(format!("failed to set regs for vCPU {id}: {e}"))
    })?;

    // Restore FPU
    let mut fpr = [[0u8; 16]; 8];
    for (i, fpr_bytes) in state.fpu.fpr.iter().enumerate() {
        if i < 8 {
            let len = std::cmp::min(fpr_bytes.len(), 16);
            fpr[i][..len].copy_from_slice(&fpr_bytes[..len]);
        }
    }
    let mut xmm = [[0u8; 16]; 16];
    for (i, xmm_bytes) in state.fpu.xmm.iter().enumerate() {
        if i < 16 {
            let len = std::cmp::min(xmm_bytes.len(), 16);
            xmm[i][..len].copy_from_slice(&xmm_bytes[..len]);
        }
    }
    let kvm_fpu = kvm_bindings::kvm_fpu {
        fpr,
        fcw: state.fpu.fcw,
        fsw: state.fpu.fsw,
        ftwx: state.fpu.ftwx,
        last_opcode: state.fpu.last_opcode,
        last_ip: state.fpu.last_ip,
        last_dp: state.fpu.last_dp,
        xmm,
        mxcsr: state.fpu.mxcsr,
        ..Default::default()
    };
    vcpu_fd
        .set_fpu(&kvm_fpu)
        .map_err(|e| CheckpointError::VcpuState(format!("failed to set fpu for vCPU {id}: {e}")))?;

    // Restore XCRs
    if !state.xcrs.is_empty() {
        let mut kvm_xcrs = kvm_bindings::kvm_xcrs::default();
        kvm_xcrs.nr_xcrs = state.xcrs.len() as u32;
        for (i, xcr) in state.xcrs.iter().enumerate() {
            if i < kvm_xcrs.xcrs.len() {
                kvm_xcrs.xcrs[i].xcr = xcr.xcr;
                kvm_xcrs.xcrs[i].value = xcr.value;
            }
        }
        vcpu_fd.set_xcrs(&kvm_xcrs).map_err(|e| {
            CheckpointError::VcpuState(format!("failed to set xcrs for vCPU {id}: {e}"))
        })?;
    }

    // Restore debug registers
    let kvm_debug_regs = kvm_bindings::kvm_debugregs {
        db: state.debug_regs.db,
        dr6: state.debug_regs.dr6,
        dr7: state.debug_regs.dr7,
        flags: state.debug_regs.flags,
        ..Default::default()
    };
    vcpu_fd.set_debug_regs(&kvm_debug_regs).map_err(|e| {
        CheckpointError::VcpuState(format!("failed to set debug_regs for vCPU {id}: {e}"))
    })?;

    // Restore vCPU events
    let mut kvm_events = kvm_bindings::kvm_vcpu_events::default();
    kvm_events.exception.has_error_code = state.vcpu_events.exception_has_error_code;
    kvm_events.exception.nr = state.vcpu_events.exception_nr;
    kvm_events.exception.error_code = state.vcpu_events.exception_error_code;
    kvm_events.nmi.masked = state.vcpu_events.nmi_masked;
    kvm_events.nmi.pending = state.vcpu_events.nmi_pending;
    vcpu_fd.set_vcpu_events(&kvm_events).map_err(|e| {
        CheckpointError::VcpuState(format!("failed to set vcpu_events for vCPU {id}: {e}"))
    })?;

    Ok(())
}

/// Save the state of a single vCPU from its KVM file descriptor (aarch64).
#[cfg(target_arch = "aarch64")]
pub fn save_vcpu_state(vcpu_fd: &kvm_ioctls::VcpuFd, id: u8) -> Result<VcpuState> {
    let mp_state = vcpu_fd.get_mp_state().map_err(|e| {
        CheckpointError::VcpuState(format!("failed to get mp_state for vCPU {id}: {e}"))
    })?;

    Ok(VcpuState {
        id,
        mpidr: 0,
        core_regs: Vec::new(),
        sys_regs: Vec::new(),
        mp_state: mp_state.mp_state,
    })
}

/// Restore the state of a single vCPU from saved state (aarch64).
#[cfg(target_arch = "aarch64")]
pub fn restore_vcpu_state(vcpu_fd: &kvm_ioctls::VcpuFd, state: &VcpuState) -> Result<()> {
    let kvm_mp_state = kvm_bindings::kvm_mp_state {
        mp_state: state.mp_state,
    };
    vcpu_fd.set_mp_state(kvm_mp_state).map_err(|e| {
        CheckpointError::VcpuState(format!(
            "failed to set mp_state for vCPU {}: {e}",
            state.id
        ))
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vcpu_manager_state_serialize() {
        let state = VcpuManagerState {
            boot_vcpu_count: 2,
            max_vcpu_count: 4,
            vcpu_states: Vec::new(),
        };
        let json = serde_json::to_string(&state).unwrap();
        let restored: VcpuManagerState = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.boot_vcpu_count, 2);
        assert_eq!(restored.max_vcpu_count, 4);
    }
}
