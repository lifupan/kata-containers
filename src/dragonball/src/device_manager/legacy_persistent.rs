// Copyright (C) 2024 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Persistent state for legacy devices checkpoint and restore.
//!
//! This module provides the serializable state structures for saving and
//! restoring legacy device states (serial, i8042, RTC) during
//! checkpoint/restore operations.

use serde_derive::{Deserialize, Serialize};

/// Saved state for the legacy device manager.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LegacyDeviceManagerState {
    /// Serial port (com1) state.
    pub com1: SerialDeviceState,
    /// Serial port (com2) state.
    pub com2: SerialDeviceState,
    /// Architecture-specific legacy device state.
    #[cfg(target_arch = "x86_64")]
    pub i8042_present: bool,
    /// RTC device presence (aarch64).
    #[cfg(target_arch = "aarch64")]
    pub rtc_present: bool,
}

/// Saved state for a serial (UART 16550) device.
///
/// The serial device state captures the UART register contents to properly
/// restore the device after a checkpoint. The actual I/O output stream is
/// reconnected during restore rather than serialized.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SerialDeviceState {
    /// Interrupt Enable Register.
    pub ier: u8,
    /// Interrupt Identification Register.
    pub iir: u8,
    /// Line Control Register.
    pub lcr: u8,
    /// Modem Control Register.
    pub mcr: u8,
    /// Line Status Register.
    pub lsr: u8,
    /// Modem Status Register.
    pub msr: u8,
    /// Scratch Register.
    pub scr: u8,
    /// Baud rate divisor (low byte).
    pub div_low: u8,
    /// Baud rate divisor (high byte).
    pub div_high: u8,
    /// Whether the FIFO is enabled.
    pub fifo_enabled: bool,
    /// Port I/O base address (x86_64) or MMIO base address (aarch64).
    pub base_address: u64,
    /// IRQ number assigned.
    pub irq: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serial_device_state_serialize() {
        let state = SerialDeviceState {
            ier: 0x01,
            iir: 0x02,
            lcr: 0x03,
            mcr: 0x0b,
            lsr: 0x60,
            msr: 0xb0,
            scr: 0x00,
            div_low: 0x01,
            div_high: 0x00,
            fifo_enabled: true,
            base_address: 0x3f8,
            irq: 4,
        };
        let json = serde_json::to_string(&state).unwrap();
        let restored: SerialDeviceState = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.ier, 0x01);
        assert_eq!(restored.base_address, 0x3f8);
        assert_eq!(restored.irq, 4);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_legacy_device_manager_state_serialize() {
        let state = LegacyDeviceManagerState {
            com1: SerialDeviceState::default(),
            com2: SerialDeviceState::default(),
            i8042_present: true,
        };
        let json = serde_json::to_string(&state).unwrap();
        let restored: LegacyDeviceManagerState = serde_json::from_str(&json).unwrap();
        assert!(restored.i8042_present);
    }
}
