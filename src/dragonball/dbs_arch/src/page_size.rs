// Copyright (C) 2025 Alibaba Cloud. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};

const PAGE_SHIFT_4K: u64 = 12;
const PAGE_SHIFT_64K: u64 = 16;
const PAGE_SIZE_4K: u64 = 1 << PAGE_SHIFT_4K;
const PAGE_SIZE_64K: u64 = 1 << PAGE_SHIFT_64K;
const PAGE_MASK_4K: u64 = !(PAGE_SIZE_4K - 1);
const PAGE_MASK_64K: u64 = !(PAGE_SIZE_64K - 1);

// Referring to linux kernel file:
// arch/arm64/include/asm/pgtable-hwdef.h
//
// Size mapped by an entry at level n ( 0 <= n <= 3)
// We map (PAGE_SHIFT - 3) at all translation levels and PAGE_SHIFT bits
// in the final page. The maximum number of translation levels supported by
// the architecture is 4. Hence, starting at level n, we have further
// ((4 - n) - 1) levels of translation excluding the offset within the page.
// So, the total number of bits mapped by an entry at level n is :
//
//  ((4 - n) - 1) * (PAGE_SHIFT - 3) + PAGE_SHIFT
//
// Rearranging it a bit we get :
//   (4 - n) * (PAGE_SHIFT - 3) + 3
const PMD_SHIFT_4K: u64 = (PAGE_SHIFT_4K - 3) * (4 - 2) + 3;
const PMD_SHIFT_64K: u64 = (PAGE_SHIFT_64K - 3) * (4 - 2) + 3;
const PMD_SIZE_4K: u64 = 1 << PMD_SHIFT_4K;
const PMD_SIZE_64K: u64 = 1 << PMD_SHIFT_64K;
const PMD_MASK_4K: u64 = !(PMD_SIZE_4K - 1);
const PMD_MASK_64K: u64 = !(PMD_SIZE_64K - 1);

const PUD_SHIFT_4K: u64 = (PAGE_SHIFT_4K - 3) * (4 - 1) + 3;
const PUD_SHIFT_64K: u64 = (PAGE_SHIFT_64K - 3) * (4 - 1) + 3;
const PUD_SIZE_4K: u64 = 1 << PUD_SHIFT_4K;
const PUD_SIZE_64K: u64 = 1 << PUD_SHIFT_64K;
const PUD_MASK_4K: u64 = !(PUD_SIZE_4K - 1);
const PUD_MASK_64K: u64 = !(PUD_SIZE_64K - 1);

//  include/linux/mmzone.h requires the following to be true:
//
//  MAX_ORDER + PAGE_SHIFT <= SECTION_SIZE_BITS
//
// so the maximum value of MAX_ORDER is SECTION_SIZE_BITS - PAGE_SHIFT:
//
//     | SECTION_SIZE_BITS |  PAGE_SHIFT  |  max MAX_ORDER  |  default MAX_ORDER |
// ----+-------------------+--------------+-----------------+--------------------+
// 4K  |       27          |      12      |       15        |         10         |
// 16K |       27          |      14      |       13        |         11         |
// 64K |       29          |      16      |       13        |         13         |
const SECTION_SIZE_BITS_4K: u64 = 27;
const SECTION_SIZE_BITS_64K: u64 = 29;

#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// Page size level
pub enum PageSizeLevel {
    #[default]
    #[serde(rename = "4k")]
    /// 4K page size
    _4K,
    #[serde(rename = "64k")]
    #[cfg(target_arch = "aarch64")]
    /// 64K page size
    _64K,
}

impl PageSizeLevel {
    fn page_shift(&self) -> u64 {
        match self {
            PageSizeLevel::_4K => PAGE_SHIFT_4K,
            #[cfg(target_arch = "aarch64")]
            PageSizeLevel::_64K => PAGE_SHIFT_64K,
        }
    }

    fn page_size(&self) -> u64 {
        match self {
            PageSizeLevel::_4K => PAGE_SIZE_4K,
            #[cfg(target_arch = "aarch64")]
            PageSizeLevel::_64K => PAGE_SIZE_64K,
        }
    }

    fn page_mask(&self) -> u64 {
        match self {
            PageSizeLevel::_4K => PAGE_MASK_4K,
            #[cfg(target_arch = "aarch64")]
            PageSizeLevel::_64K => PAGE_MASK_64K,
        }
    }

    fn pmd_shift(&self) -> u64 {
        match self {
            PageSizeLevel::_4K => PMD_SHIFT_4K,
            #[cfg(target_arch = "aarch64")]
            PageSizeLevel::_64K => PMD_SHIFT_64K,
        }
    }

    fn pmd_size(&self) -> u64 {
        match self {
            PageSizeLevel::_4K => PMD_SIZE_4K,
            #[cfg(target_arch = "aarch64")]
            PageSizeLevel::_64K => PMD_SIZE_64K,
        }
    }

    fn pmd_mask(&self) -> u64 {
        match self {
            PageSizeLevel::_4K => PMD_MASK_4K,
            #[cfg(target_arch = "aarch64")]
            PageSizeLevel::_64K => PMD_MASK_64K,
        }
    }

    fn pud_shift(&self) -> u64 {
        match self {
            PageSizeLevel::_4K => PUD_SHIFT_4K,
            #[cfg(target_arch = "aarch64")]
            PageSizeLevel::_64K => PUD_SHIFT_64K,
        }
    }

    fn pud_size(&self) -> u64 {
        match self {
            PageSizeLevel::_4K => PUD_SIZE_4K,
            #[cfg(target_arch = "aarch64")]
            PageSizeLevel::_64K => PUD_SIZE_64K,
        }
    }

    fn pud_mask(&self) -> u64 {
        match self {
            PageSizeLevel::_4K => PUD_MASK_4K,
            #[cfg(target_arch = "aarch64")]
            PageSizeLevel::_64K => PUD_MASK_64K,
        }
    }

    fn section_size_bits(&self) -> u64 {
        match self {
            PageSizeLevel::_4K => SECTION_SIZE_BITS_4K,
            #[cfg(target_arch = "aarch64")]
            PageSizeLevel::_64K => SECTION_SIZE_BITS_64K,
        }
    }
}

static PAGE_SIZE_LEVEL: OnceCell<PageSizeLevel> = OnceCell::new();

/// Get the page shift value.
pub fn page_shift() -> u64 {
    let page_size_level = PAGE_SIZE_LEVEL.get_or_init(PageSizeLevel::default);
    page_size_level.page_shift()
}

/// Get the page size value.
pub fn page_size() -> u64 {
    let page_size_level = PAGE_SIZE_LEVEL.get_or_init(PageSizeLevel::default);
    page_size_level.page_size()
}

/// Get the page mask value.
pub fn page_mask() -> u64 {
    let page_size_level = PAGE_SIZE_LEVEL.get_or_init(PageSizeLevel::default);
    page_size_level.page_mask()
}

/// Get the pmd shift value.
pub fn pmd_shift() -> u64 {
    let page_size_level = PAGE_SIZE_LEVEL.get_or_init(PageSizeLevel::default);
    page_size_level.pmd_shift()
}

/// Get the pmd size value.
pub fn pmd_size() -> u64 {
    let page_size_level = PAGE_SIZE_LEVEL.get_or_init(PageSizeLevel::default);
    page_size_level.pmd_size()
}

/// Get the pmd mask value.
pub fn pmd_mask() -> u64 {
    let page_size_level = PAGE_SIZE_LEVEL.get_or_init(PageSizeLevel::default);
    page_size_level.pmd_mask()
}

/// Get the pud shift value.
pub fn pud_shift() -> u64 {
    let page_size_level = PAGE_SIZE_LEVEL.get_or_init(PageSizeLevel::default);
    page_size_level.pud_shift()
}

/// Get the pud size value.
pub fn pud_size() -> u64 {
    let page_size_level = PAGE_SIZE_LEVEL.get_or_init(PageSizeLevel::default);
    page_size_level.pud_size()
}

/// Get the pud mask value.
pub fn pud_mask() -> u64 {
    let page_size_level = PAGE_SIZE_LEVEL.get_or_init(PageSizeLevel::default);
    page_size_level.pud_mask()
}

/// Get the section size bits value.
pub fn section_size_bits() -> u64 {
    let page_size_level = PAGE_SIZE_LEVEL.get_or_init(PageSizeLevel::default);
    page_size_level.section_size_bits()
}


#[cfg(test)]
mod tests {
    use super::*;

    // Reset the global static variable before each test
    fn reset_global() {
        unsafe {
            // transfer the pointer to a mutable pointer
            let cell = &PAGE_SIZE_LEVEL as *const OnceCell<_> as *mut OnceCell<PageSizeLevel>;

            // take it out
            (*cell).take();
        }
    }

    #[test]
    fn test_page_size_default_page_shift() {
        reset_global();
        assert_eq!(page_shift(), PAGE_SHIFT_4K);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_page_size_set_page_shift_to_64k() {
        reset_global();
        set_page_size_level(PageSizeLevel::_64K).unwrap();
        assert_eq!(page_shift(), PAGE_SHIFT_64K);
    }

    #[test]
    fn test_page_size_default_page_size() {
        reset_global();
        assert_eq!(page_size(), PAGE_SIZE_4K);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_page_size_set_page_size_to_64k() {
        reset_global();
        set_page_size_level(PageSizeLevel::_64K).unwrap();
        assert_eq!(page_size(), PAGE_SIZE_64K);
    }

    #[test]
    fn test_page_size_default_page_mask() {
        reset_global();
        assert_eq!(page_mask(), PAGE_MASK_4K);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_page_size_set_page_mask_to_64k() {
        reset_global();
        set_page_size_level(PageSizeLevel::_64K).unwrap();
        assert_eq!(page_mask(), PAGE_MASK_64K);
    }

    #[test]
    fn test_page_size_default_pmd_shift() {
        reset_global();
        assert_eq!(pmd_shift(), PMD_SHIFT_4K);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_page_size_set_pmd_shift_to_64k() {
        reset_global();
        set_page_size_level(PageSizeLevel::_64K).unwrap();
        assert_eq!(pmd_shift(), PMD_SHIFT_64K);
    }

    #[test]
    fn test_page_size_default_pmd_size() {
        reset_global();
        assert_eq!(pmd_size(), PMD_SIZE_4K);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_page_size_set_pmd_size_to_64k() {
        reset_global();
        set_page_size_level(PageSizeLevel::_64K).unwrap();
        assert_eq!(pmd_size(), PMD_SIZE_64K);
    }

    #[test]
    fn test_page_size_default_pmd_mask() {
        reset_global();
        assert_eq!(pmd_mask(), PMD_MASK_4K);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_page_size_set_pmd_mask_to_64k() {
        reset_global();
        set_page_size_level(PageSizeLevel::_64K).unwrap();
        assert_eq!(pmd_mask(), PMD_MASK_64K);
    }

    #[test]
    fn test_page_size_default_pud_shift() {
        reset_global();
        assert_eq!(pud_shift(), PUD_SHIFT_4K);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_page_size_set_pud_shift_to_64k() {
        reset_global();
        set_page_size_level(PageSizeLevel::_64K).unwrap();
        assert_eq!(pud_shift(), PUD_SHIFT_64K);
    }

    #[test]
    fn test_page_size_default_pud_size() {
        reset_global();
        assert_eq!(pud_size(), PUD_SIZE_4K);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_page_size_set_pud_size_to_64k() {
        reset_global();
        set_page_size_level(PageSizeLevel::_64K).unwrap();
        assert_eq!(pud_size(), PUD_SIZE_64K);
    }

    #[test]
    fn test_page_size_default_pud_mask() {
        reset_global();
        assert_eq!(pud_mask(), PUD_MASK_4K);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_page_size_set_pud_mask_to_64k() {
        reset_global();
        set_page_size_level(PageSizeLevel::_64K).unwrap();
        assert_eq!(pud_mask(), PUD_MASK_64K);
    }

    #[test]
    fn test_page_size_default_section_size_bits() {
        reset_global();
        assert_eq!(section_size_bits(), SECTION_SIZE_BITS_4K);
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn test_page_size_set_section_size_bits_to_64k() {
        reset_global();
        set_page_size_level(PageSizeLevel::_64K).unwrap();
        assert_eq!(section_size_bits(), SECTION_SIZE_BITS_64K);
    }

    #[test]
    fn test_page_size_set_page_size_level_once() {
        reset_global();
        assert!(set_page_size_level(PageSizeLevel::_4K).is_ok());
    }

    #[test]
    fn test_page_size_set_page_size_level_twice() {
        reset_global();
        set_page_size_level(PageSizeLevel::_4K).unwrap();
        assert!(set_page_size_level(PageSizeLevel::_4K).is_err());
    }
}
