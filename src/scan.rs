use crate::MemHook;

use std::mem::{size_of, MaybeUninit};

use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    PAGE_READWRITE, PAGE_WRITECOPY,
};

use subslice::SubsliceExt;

const PAGE_PROTECTION_MASK: u32 =
    PAGE_EXECUTE_READWRITE.0 | PAGE_EXECUTE_WRITECOPY.0 | PAGE_READWRITE.0 | PAGE_WRITECOPY.0;

pub fn aob_scan(
    memhook: &MemHook,
    bytes: &[u8],
    start: Option<usize>,
    end: Option<usize>,
) -> Vec<usize> {
    let start = start.unwrap_or(0);
    let end = end.unwrap_or(usize::MAX);

    let pages = memory_regions(&memhook)
        .into_iter()
        .filter(|p| p.Protect.0 & PAGE_PROTECTION_MASK != 0)
        .filter(|p| {
            let (reg_start, reg_end) = (
                p.BaseAddress as usize,
                p.BaseAddress as usize + p.RegionSize,
            );
            reg_start <= end && start <= reg_end
        });

    let mut results = Vec::new();
    for page in pages {
        let reg_start = page.BaseAddress as usize;
        let bytes_to_read = page.RegionSize;

        let data = memhook.read_bytes(reg_start as usize, bytes_to_read);
        if data == None {
            continue;
        }
        results.extend(
            subslice_positions(&data.unwrap(), &bytes)
                .into_iter()
                .map(|x| x + reg_start),
        );
    }
    results
}

fn subslice_positions(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut result = Vec::new();
    if needle.len() == 0 {
        return result;
    }

    let mut index: usize = 0;
    loop {
        if let Some(pos) = haystack[index..].find(needle) {
            result.push(index + pos);
            index += pos + 1;
        } else {
            break;
        }
    }
    result
}

fn memory_regions(memhook: &MemHook) -> Vec<MEMORY_BASIC_INFORMATION> {
    let mut base: usize = 0;
    let mut regions = Vec::new();
    let mut region_info = MaybeUninit::uninit();

    loop {
        let successful = unsafe {
            VirtualQueryEx(
                memhook.handle,
                base as *const _,
                region_info.as_mut_ptr(),
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if successful == 0 {
            break regions;
        }

        let region_info = unsafe { region_info.assume_init() };
        base = region_info.BaseAddress as usize + region_info.RegionSize;
        regions.push(region_info);
    }
}
