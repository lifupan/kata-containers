// Copyright (C) 2024 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Persistent state for the console manager checkpoint and restore.
//!
//! This module provides the serializable state structures for saving and
//! restoring console manager state during checkpoint/restore operations.

use serde_derive::{Deserialize, Serialize};

/// Console backend type.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConsoleBackendType {
    /// Standard input/output backend.
    Stdio,
    /// Unix domain socket backend with socket path.
    UnixSocket(String),
    /// No backend configured.
    None,
}

/// Saved state for the console manager.
///
/// The actual file descriptors and connections cannot be serialized, so
/// during restore we re-create the connections based on the backend type
/// and path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsoleManagerState {
    /// Type of console backend in use.
    pub backend_type: ConsoleBackendType,
}

impl Default for ConsoleManagerState {
    fn default() -> Self {
        ConsoleManagerState {
            backend_type: ConsoleBackendType::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_console_manager_state_serialize() {
        let state = ConsoleManagerState {
            backend_type: ConsoleBackendType::UnixSocket("/tmp/console.sock".to_string()),
        };
        let json = serde_json::to_string(&state).unwrap();
        let restored: ConsoleManagerState = serde_json::from_str(&json).unwrap();
        assert_eq!(
            restored.backend_type,
            ConsoleBackendType::UnixSocket("/tmp/console.sock".to_string())
        );
    }

    #[test]
    fn test_console_manager_state_default() {
        let state = ConsoleManagerState::default();
        assert_eq!(state.backend_type, ConsoleBackendType::None);
    }
}
