// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright (C) 2025 Ant Group. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines functionality for creating guest memory snapshots.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};

use dbs_address_space::AddressSpace;
use dbs_arch::page_size;
use snapshot::Persist;
use versionize::{VersionMap, Versionize, VersionizeResult};
use versionize_derive::Versionize;
#[cfg(feature = "vm-snapshot")]
use vm_memory::mmap::persist::GuestRegionMmapState;
use vm_memory::{
    Bytes, FileOffset, GuestAddress, GuestMemoryError, GuestMemoryMmap, GuestMemoryRegion,
    GuestRegionMmap, MemoryRegionAddress, MmapRegion,
};

use crate::resource_manager::ResourceError;

pub type DirtyBitmap = HashMap<usize, Vec<u64>>;

/// State of a guest memory region saved to file/buffer.
#[derive(Debug, PartialEq, Versionize)]
pub struct GuestMemoryRegionState {
    /// Base address
    pub base_address: u64,
    /// Region size
    pub size: usize,
    /// Offset in file/buffer where the region is saved
    pub offset: u64,
}

/// Guest memory state
#[derive(Debug, Default, PartialEq, Versionize)]
pub struct GuestMemoryState {
    /// List of regions
    pub regions: Vec<GuestMemoryRegionState>,
}

#[cfg(feature = "vm-snapshot")]
/// Guest memory state when doing live upgrade
#[derive(Debug, Versionize, PartialEq)]
pub struct GuestMemoryLiveUpgradeState {
    /// List of regions
    pub regions: Vec<GuestRegionMmapState>,
}

/// Errors associated with dumping guest memory to file.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Cannot access file
    #[error("Cannot access file: {0:?}")]
    FileHandle(#[source] std::io::Error),
    /// Cannot create memory
    #[error("Cannot create memory: {0:?}")]
    CreateMemory(#[source] vm_memory::Error),
    /// Cannot create region
    #[error("Cannot create memory region: {0:?}")]
    CreateRegion(#[source] vm_memory::mmap::MmapRegionError),
    /// Cannot dump memory
    #[error("Cannot dump memory: {0:?}")]
    WriteMemory(#[source] GuestMemoryError),
    /// Cannot set uwer memory region
    #[error("Cannot set user memory region: {0:?}")]
    SetUserMemoryRegion(#[source] kvm_ioctls::Error),
    /// Cannot mmap memory fd
    #[error("Cannot mmap memory fd: {0:?}")]
    MemoryMmap(#[source] std::io::Error),
    /// Madvise Error
    #[error("Madvise error: {0:?}")]
    Madvise(#[source] nix::Error),
    /// Cannot find memory region
    #[error("Cannot find memory region: {0:?}")]
    FindRegion(GuestAddress),
    /// Get slot from base_to_slot failed.
    #[error("Get slot failed with base {0:?}")]
    GetSlot(GuestAddress),
    /// Resource manager init memory pool failed.
    #[error("Resource manager init memory pool failed: {0:?}")]
    InitMemoryPool(ResourceError),
}

type Result = std::result::Result<(), Error>;

/// Defines the interfaces for snapshotting memory.
pub trait SnapshotMemory
where
    Self: Sized,
{
    /// Describing GuestMemoryMmap through a GuestMemoryState struct.
    fn describe(&self, address_space: Option<&AddressSpace>) -> GuestMemoryState;
    /// Dumps all contents GuestMemoryMmap
    fn dump<T: Write + Seek>(&self, writer: &mut T, address_space: Option<&AddressSpace>)
        -> Result;
    /// Dumps all pages of GuestMemoryMmap present in `dirty_bitmap` to a writter.
    fn dump_dirty<T: Write + Seek>(&self, writer: &mut T, dirty_bitmap: &DirtyBitmap) -> Result;

    #[cfg(feature = "vm-snapshot")]
    /// Get the GuestMemoryState when doing live upgrade
    fn live_upgrade_save(&self, address_space: &AddressSpace) -> GuestMemoryLiveUpgradeState;

    #[cfg(feature = "vm-snapshot")]
    /// Get GuestMemoryMmap when doing live upgrade
    fn live_upgrade_restore(
        state: &GuestMemoryLiveUpgradeState,
    ) -> std::result::Result<Self, Error>;
    /// Creates a GuestMemoryMmap given a `file` containing the data , a `state`
    /// containing mapping information, and `is_gshmem` indeciates the file is
    /// on gshmem fs or not.
    fn restore(
        file: &File,
        state: &GuestMemoryState,
        is_gshmem: bool,
    ) -> std::result::Result<Self, Error>;
}

struct ZeroPage {
    addr: *const libc::c_void,
}

impl ZeroPage {
    pub fn new() -> Self {
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page_size() as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        // Currenty, kernel returns zero page at first read page fault.
        // If zero page is disabled in the future, we must zero this page manually.
        Self { addr }
    }

    // Area [addr, addr + page_size] must be mapped
    pub fn is_page_equal(&self, addr: *const libc::c_void) -> bool {
        let diff = unsafe { libc::memcmp(addr, self.addr, page_size() as usize) };
        diff == 0
    }
}

impl Drop for ZeroPage {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.addr as *mut libc::c_void, page_size() as usize) };
    }
}

impl SnapshotMemory for GuestMemoryMmap {
    fn describe(&self, address_space: Option<&AddressSpace>) -> GuestMemoryState {
        let mut memory_state = GuestMemoryState::default();
        let mut offset = 0;
        for region in self.iter() {
            // In snapshot save/restore scenarios, AddressSpaceRegionType::DAXMemory
            // should not be saved and restored by vm_as. Because this type memory is
            // private to the device, it should be initialized by the device itself.
            // For example, DAX memory should not be saved and restored by vm_as, but by
            // the virtio-fs device.
            //
            // Same to DeviceMemory.
            if let Some(address_space) = address_space {
                if address_space.is_dax_region(region.start_addr())
                    || address_space.is_device_region(region.start_addr())
                {
                    continue;
                }
            }

            memory_state.regions.push(GuestMemoryRegionState {
                base_address: region.start_addr().0,
                size: region.len() as usize,
                offset,
            });

            offset += region.len();
        }
        memory_state
    }

    fn dump<T: Write + Seek>(
        &self,
        writer: &mut T,
        address_space: Option<&AddressSpace>,
    ) -> Result {
        // Skip zero pages with the help of sparse file to reduce saved data
        // Spare file is supported by most modern filesystems, so there is no
        // need to check filesystem capability.
        let zero_page = ZeroPage::new();
        for region in self.iter() {
            if let Some(address_space) = address_space {
                if address_space.is_dax_region(region.start_addr()) {
                    continue;
                }
            }

            let mut offset = 0;
            while offset < region.len() {
                // If region size is not page_size-aligned, write the tail
                // Since start addr of region comes from mmap, it is always aligned.
                if region.len() - offset < page_size() {
                    region
                        .write_all_to(
                            MemoryRegionAddress(offset),
                            writer,
                            (region.len() - offset) as usize,
                        )
                        .map_err(Error::WriteMemory)?;
                    break;
                }

                let host_addr = region
                    .get_host_address(MemoryRegionAddress(offset))
                    .map_err(Error::WriteMemory)?;
                if zero_page.is_page_equal(host_addr as *const libc::c_void) {
                    writer
                        .seek(SeekFrom::Current(page_size() as i64))
                        .map_err(Error::FileHandle)?;
                } else {
                    region
                        .write_all_to(MemoryRegionAddress(offset), writer, page_size() as usize)
                        .map_err(Error::WriteMemory)?;
                }
                offset += page_size();
            }
        }
        Ok(())
    }

    fn dump_dirty<T: Write + Seek>(&self, writer: &mut T, dirty_bitmap: &DirtyBitmap) -> Result {
        let page_size = page_size() as usize;
        let mut writer_offset = 0;

        for (slot, region) in self.iter().enumerate() {
            let bitmap = dirty_bitmap.get(&slot).unwrap();
            let mut write_size = 0;
            let mut dirty_batch_start: u64 = 0;

            for (i, v) in bitmap.iter().enumerate() {
                for j in 0..64 {
                    let is_dirty_page = ((v >> j) & 1u64) != 0u64;
                    if is_dirty_page {
                        let page_offset = ((i * 64) + j) * page_size;
                        // we are at the start of a new batch of dirty pages.
                        if write_size == 0 {
                            // Seek forward over the unmodified pages.
                            writer
                                .seek(SeekFrom::Start(writer_offset + page_offset as u64))
                                .map_err(Error::FileHandle)?;
                            dirty_batch_start = page_offset as u64;
                        }
                        write_size += page_size;
                    } else if write_size > 0 {
                        // We are at the end of a batch of dirty pages.
                        region
                            .write_all_to(
                                MemoryRegionAddress(dirty_batch_start),
                                writer,
                                write_size,
                            )
                            .map_err(Error::WriteMemory)?;
                        write_size = 0;
                    }
                }
            }

            if write_size > 0 {
                region
                    .write_all_to(MemoryRegionAddress(dirty_batch_start), writer, write_size)
                    .map_err(Error::WriteMemory)?;
            }

            writer_offset += region.len();
        }
        Ok(())
    }

    #[cfg(feature = "vm-snapshot")]
    fn live_upgrade_save(&self, address_space: &AddressSpace) -> GuestMemoryLiveUpgradeState {
        let mut regions = Vec::new();
        // safe to unwrap
        for region in self.iter() {
            // Vfio device need to active after upgrade, and then DeviceMemory will be added to vm_as/address_space.
            // So we should not save DeviceMemory here.
            if address_space.is_device_region(region.start_addr()) {
                continue;
            }
            regions.push(region.live_upgrade_save());
        }

        GuestMemoryLiveUpgradeState { regions }
    }

    #[cfg(feature = "vm-snapshot")]
    fn live_upgrade_restore(
        state: &GuestMemoryLiveUpgradeState,
    ) -> std::result::Result<Self, Error> {
        let mut regions = Vec::new();
        for region in state.regions.iter() {
            regions.push(
                GuestRegionMmap::live_upgrade_restore((), region).map_err(Error::MemoryMmap)?,
            );
        }
        Self::from_regions(regions).map_err(Error::CreateMemory)
    }

    fn restore(
        file: &File,
        state: &GuestMemoryState,
        is_gshmem: bool,
    ) -> std::result::Result<Self, Error> {
        let mut mmap_regions = Vec::new();

        let flags = if is_gshmem {
            libc::MAP_SHARED
        } else {
            libc::MAP_NORESERVE | libc::MAP_PRIVATE
        };

        for region in state.regions.iter() {
            let mmap_region = MmapRegion::build(
                Some(FileOffset::new(
                    file.try_clone().map_err(Error::FileHandle)?,
                    region.offset,
                )),
                region.size,
                libc::PROT_READ | libc::PROT_WRITE,
                flags,
                None,
            )
            .map(|r| GuestRegionMmap::new(r, GuestAddress(region.base_address)))
            .map_err(Error::CreateRegion)?
            .map_err(Error::CreateMemory)?;

            mmap_regions.push(mmap_region);
        }

        Self::from_regions(mmap_regions).map_err(Error::CreateMemory)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::mem::ManuallyDrop;
    use std::sync::Arc;

    use address_space::{AddressSpaceRegion, AddressSpaceRegionType};
    use utils::tempfile::TempFile;
    use vm_memory::{GuestAddress, GuestMemory, GuestUsize};

    use super::*;
    use crate::test_utils::tests::create_address_space_layout;

    const GUEST_PHYS_END: u64 = (1 << 46) - 1;
    const GUEST_MEM_END: u64 = GUEST_PHYS_END >> 1;
    const GUEST_DEVICE_START: u64 = GUEST_MEM_END + 1;

    // create address_space from mem
    pub(crate) fn create_address_space_from_ranges(
        ranges: &[(GuestAddress, usize)],
        ty: AddressSpaceRegionType,
    ) -> AddressSpace {
        let mut address_space_region = vec![];
        for range in ranges {
            address_space_region.push(Arc::new(AddressSpaceRegion::new(
                ty,
                range.0 as GuestAddress,
                range.1 as GuestUsize,
            )));
        }
        if address_space_region.is_empty() {
            panic!("address_space_region's len is 0 after create_address_space");
        }
        let layout = create_address_space_layout();
        AddressSpace::from_regions(address_space_region, layout)
    }

    #[test]
    fn test_persist_describe_state() {
        let page_size = page_size() as usize;

        // Two regions of one page each, with a one page gap between them.
        let mem_regions = [
            (GuestAddress(0), page_size),
            (GuestAddress(page_size as u64 * 2), page_size),
        ];
        let guest_memory = GuestMemoryMmap::from_ranges(&mem_regions[..]).unwrap();

        let expected_memory_state = GuestMemoryState {
            regions: vec![
                GuestMemoryRegionState {
                    base_address: 0,
                    size: page_size,
                    offset: 0,
                },
                GuestMemoryRegionState {
                    base_address: page_size as u64 * 2,
                    size: page_size,
                    offset: page_size as u64,
                },
            ],
        };

        let actual_memory_state = guest_memory.describe(None);
        assert_eq!(expected_memory_state, actual_memory_state);

        // Two regions of three pages each, with a one page gap between them.
        let mem_regions = [
            (GuestAddress(0), page_size * 3),
            (GuestAddress(page_size as u64 * 4), page_size * 3),
        ];
        let guest_memory = GuestMemoryMmap::from_ranges(&mem_regions[..]).unwrap();

        let expected_memory_state = GuestMemoryState {
            regions: vec![
                GuestMemoryRegionState {
                    base_address: 0,
                    size: page_size * 3,
                    offset: 0,
                },
                GuestMemoryRegionState {
                    base_address: page_size as u64 * 4,
                    size: page_size * 3,
                    offset: page_size as u64 * 3,
                },
            ],
        };

        let actual_memory_state = guest_memory.describe(None);
        assert_eq!(expected_memory_state, actual_memory_state);

        // test describe memory with DAX region
        {
            let dax_start = GUEST_DEVICE_START;
            let mem_regions = [
                (GuestAddress(0), page_size),
                (GuestAddress(page_size as u64 * 2), page_size),
                (GuestAddress(dax_start), page_size),
            ];
            let guest_memory = GuestMemoryMmap::from_ranges(&mem_regions[..]).unwrap();

            let expected_memory_state = GuestMemoryState {
                regions: vec![
                    GuestMemoryRegionState {
                        base_address: 0,
                        size: page_size,
                        offset: 0,
                    },
                    GuestMemoryRegionState {
                        base_address: page_size as u64 * 2,
                        size: page_size,
                        offset: page_size as u64,
                    },
                ],
            };

            let tmp_regions = [(GuestAddress(dax_start), page_size)];

            let address_space = create_address_space_from_ranges(
                &tmp_regions[..],
                AddressSpaceRegionType::DAXMemory,
            );

            let actual_memory_state = guest_memory.describe(Some(&address_space));
            assert_eq!(expected_memory_state, actual_memory_state);
        }
    }

    #[test]
    fn test_persist_restore_memory() {
        let page_size = page_size() as usize;

        // Two regions of two pages each, with a one page gap between them.
        let mem_regions = [
            (GuestAddress(0), page_size * 2),
            (GuestAddress(page_size as u64 * 3), page_size * 2),
        ];
        let guest_memory = GuestMemoryMmap::from_ranges(&mem_regions[..]).unwrap();

        // Fill the first region with 1s and the second with 2s.
        let first_region = vec![1u8; page_size * 2];
        guest_memory
            .write(&first_region[..], GuestAddress(0))
            .unwrap();

        let second_region = vec![2u8; page_size * 2];
        guest_memory
            .write(&second_region[..], GuestAddress(page_size as u64 * 3))
            .unwrap();

        let memory_state = guest_memory.describe(None);

        // Case 1: dump the full memory.
        {
            let memory_file = TempFile::new().unwrap();
            guest_memory.dump(&mut memory_file.as_file(), None).unwrap();

            let restored_guest_memory =
                GuestMemoryMmap::restore(memory_file.as_file(), &memory_state, false).unwrap();

            // Check that the region contents are the same.
            let mut actual_region = vec![0u8; page_size * 2];
            restored_guest_memory
                .read(actual_region.as_mut_slice(), GuestAddress(0))
                .unwrap();
            assert_eq!(first_region, actual_region);

            restored_guest_memory
                .read(
                    actual_region.as_mut_slice(),
                    GuestAddress(page_size as u64 * 3),
                )
                .unwrap();
            assert_eq!(second_region, actual_region);
        }

        // Case 2: dump only the dirty pages.
        {
            // First region pages: [dirty, clean]
            // Second region pages: [clean, dirty]
            let mut dirty_bitmap: DirtyBitmap = HashMap::new();
            dirty_bitmap.insert(0, vec![0b01; 1]);
            dirty_bitmap.insert(1, vec![0b10; 1]);

            let file = TempFile::new().unwrap();
            guest_memory
                .dump_dirty(&mut file.as_file(), &dirty_bitmap)
                .unwrap();

            let restored_guest_memory =
                GuestMemoryMmap::restore(file.as_file(), &memory_state, false).unwrap();

            // Check that only the dirty pages have been restored.
            let zeros = vec![0u8; page_size];
            let ones = vec![1u8; page_size];
            let twos = vec![2u8; page_size];
            let expected_first_region = [ones.as_slice(), zeros.as_slice()].concat();
            let expected_second_region = [zeros.as_slice(), twos.as_slice()].concat();

            let mut actual_region = vec![0u8; page_size * 2];
            restored_guest_memory
                .read(actual_region.as_mut_slice(), GuestAddress(0))
                .unwrap();
            assert_eq!(expected_first_region, actual_region);

            restored_guest_memory
                .read(
                    actual_region.as_mut_slice(),
                    GuestAddress(page_size as u64 * 3),
                )
                .unwrap();
            assert_eq!(expected_second_region, actual_region);
        }

        // test dump memory with DAX region
        {
            // Two regions of two pages each, with a one page gap between them.
            let dax_start = GUEST_DEVICE_START;
            let mem_regions = [
                (GuestAddress(0), page_size * 2),
                (GuestAddress(page_size as u64 * 3), page_size * 2),
                (GuestAddress(dax_start), page_size * 2),
            ];
            let guest_memory = GuestMemoryMmap::from_ranges(&mem_regions[..]).unwrap();

            let tmp_regions = [(GuestAddress(dax_start), page_size)];

            let address_space = create_address_space_from_ranges(
                &tmp_regions[..],
                AddressSpaceRegionType::DAXMemory,
            );

            // Fill the first region with 1s and the second with 2s.
            let first_region = vec![1u8; page_size * 2];
            guest_memory
                .write(&first_region[..], GuestAddress(0))
                .unwrap();

            let second_region = vec![2u8; page_size * 2];
            guest_memory
                .write(&second_region[..], GuestAddress(page_size as u64 * 3))
                .unwrap();

            let memory_state = guest_memory.describe(Some(&address_space));

            let memory_file = TempFile::new().unwrap();
            guest_memory
                .dump(&mut memory_file.as_file(), Some(&address_space))
                .unwrap();

            let restored_guest_memory =
                GuestMemoryMmap::restore(memory_file.as_file(), &memory_state, false).unwrap();

            assert_eq!(restored_guest_memory.num_regions(), 2);
        }
    }

    #[test]
    fn test_persist_live_upgrade_save_restore() {
        let page_size = page_size() as usize;

        // Two regions of two pages each, with a one page gap between them.
        let mem_regions = [
            (GuestAddress(0), page_size * 2),
            (GuestAddress(page_size as u64 * 3), page_size * 2),
        ];
        let guest_memory = GuestMemoryMmap::from_ranges(&mem_regions[..]).unwrap();

        // Fill the first region with 1s and the second with 2s.
        let first_region = vec![1u8; page_size * 2];
        guest_memory
            .write(&first_region[..], GuestAddress(0))
            .unwrap();

        let second_region = vec![2u8; page_size * 2];
        guest_memory
            .write(&second_region[..], GuestAddress(page_size as u64 * 3))
            .unwrap();

        let address_space = create_address_space_from_ranges(
            &mem_regions[..],
            AddressSpaceRegionType::DefaultMemory,
        );
        let memory_state = guest_memory.live_upgrade_save(&address_space);

        let restored_guest_memory =
            ManuallyDrop::new(GuestMemoryMmap::live_upgrade_restore(&memory_state).unwrap());

        // Check that the region contents are the same.
        let mut actual_region = vec![0u8; page_size * 2];
        restored_guest_memory
            .read(actual_region.as_mut_slice(), GuestAddress(0))
            .unwrap();
        assert_eq!(first_region, actual_region);

        restored_guest_memory
            .read(
                actual_region.as_mut_slice(),
                GuestAddress(page_size as u64 * 3),
            )
            .unwrap();
        assert_eq!(second_region, actual_region);
    }
}
