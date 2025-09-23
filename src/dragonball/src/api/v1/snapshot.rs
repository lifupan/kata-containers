// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Configurations used in the snapshotting context.

use std::path::PathBuf;

use serde_derive::{Deserialize, Serialize};

#[cfg(feature = "dump")]
use super::dump::DumpConfigInfo;

/// The snapshot type options that are available when
/// creating a new snapshot.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub enum SnapshotType {
    /// Diff snapshot.
    Diff,
    /// Full snapshot.
    #[default]
    Full,
}

/// Stores the configuration that will be used for creating a snapshot.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSnapshotParams {
    /// This marks the type of snapshot we want to create.
    /// The default value is `Full`, which means a full snapshot.
    #[serde(default = "SnapshotType::default")]
    pub snapshot_type: SnapshotType,
    /// Path to the file that will contain the microVM state.
    pub snapshot_path: PathBuf,
    /// Path to the file that will contain the guest memory.
    pub mem_file_path: PathBuf,
    /// Optional field for the microVM version. The default
    /// value is the current version.
    pub version: Option<String>,
    /// save debug info of snapshot.
    pub debug: Option<bool>,
}

/// Required changes to the state when loading the snapshot
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct LoadSnapshotStateVariation {
    /// console serial path for new instance
    pub serial_path: Option<String>,
    /// Vsock info for new instance
    /// (uds path, tcp addr)
    pub vsock_info: (Option<String>, Option<String>),
    /// block paths for new instance
    /// (id, path)
    pub block_paths: Vec<(String, String)>,
    /// net devices for new instance
    /// (id, hostdev name, tap mac)
    pub net_devices: Vec<(String, String, Option<String>)>,
    /// virtiofs root path for new instance
    /// (fs_mount_point, root_path)
    pub virtiofs_roots: Vec<(String, String)>,
    #[cfg(feature = "dump")]
    /// dump related config for audo dump when guest panic
    pub dump_config: DumpConfigInfo,
}

/// Stores the configuration that will be used for loading a snapshot.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadSnapshotParams {
    /// Path to the file that contains the microVM state to be loaded.
    pub snapshot_path: PathBuf,
    /// Path to the file that contains the guest memory to be loaded.
    pub mem_file_path: PathBuf,
    /// Setting this flag will enable KVM dirty page tracking and will
    /// allow taking subsequent incremental snapshots.
    #[serde(default)]
    pub enable_diff_snapshots: bool,
    /// state variations when load snapshot
    #[serde(default)]
    pub state_variation: Option<LoadSnapshotStateVariation>,
    /// Is memory snapshot in gshmem file system.
    #[serde(default)]
    pub is_gshmem: bool,
}

/// The microVM state options.
#[derive(Debug, Deserialize, Serialize)]
pub enum VmState {
    /// The microVM is paused, which means that we can create a snapshot of it.
    Paused,
    /// The microVM is resumed; this state should be set after we load a snapshot.
    Resumed,
}

/// Keeps the microVM state necessary in the snapshotting context.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Vm {
    /// The microVM state, which can be `paused` or `resumed`.
    pub state: VmState,
}