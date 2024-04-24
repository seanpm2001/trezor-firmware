use alloc_traits::{LocalAlloc, NonZeroLayout};
use without_alloc::{alloc::LeakedAllocation, Uninit};

pub fn alloc_layout<'alloc>(
    allocator: &'alloc dyn LocalAlloc<'alloc>,
    layout: NonZeroLayout,
) -> Option<LeakedAllocation<'alloc>> {
    let alloc = allocator.alloc(layout)?;
    // SAFETY: The memory is:
    // - freshly allocated so unaliased and we can write arbitrary data to it
    // - properly aligned and of the right size
    let uninit = unsafe { Uninit::from_memory(alloc.ptr, alloc.layout.size().into()) };

    Some(LeakedAllocation { uninit })
}

pub fn alloc_t<'alloc, T>(
    allocator: &'alloc dyn LocalAlloc<'alloc>,
) -> Option<LeakedAllocation<'alloc, T>> {
    match NonZeroLayout::new::<T>() {
        None => Some(LeakedAllocation::zst_fake_alloc()),
        Some(alloc) => {
            let allocation = alloc_layout(allocator, alloc)?;
            let right_type = LeakedAllocation {
                uninit: allocation.uninit.cast().ok()?,
            };
            Some(right_type)
        }
    }
}

pub fn copy_slice<'alloc, T: Copy>(
    allocator: &'alloc dyn LocalAlloc<'alloc>,
    slice: &[T],
) -> Option<&'alloc mut [T]> {
    let layout = core::alloc::Layout::for_value(slice);
    let uninit = match NonZeroLayout::from_layout(layout.into()) {
        None => Uninit::empty(),
        Some(layout) => {
            let allocation = alloc_layout(allocator, layout)?;
            let right_type = LeakedAllocation {
                uninit: allocation.uninit.cast_slice().ok()?,
            };
            right_type.uninit
        }
    };

    unsafe {
        // SAFETY:
        // * the source is trivially valid for reads as it is a slice
        // * the memory is valid for the same layout as slice, so aligned and large
        //   enough
        // * both are aligned, uninit due to allocator requirements
        core::ptr::copy(slice.as_ptr(), uninit.as_begin_ptr(), slice.len());
    }

    Some(unsafe {
        // SAFETY: this is a copy of `slice` which is initialized.
        uninit.into_mut()
    })
}

pub fn copy_str<'alloc>(allocator: &'alloc dyn LocalAlloc<'alloc>, st: &str) -> Option<&'alloc str> {
    let bytes = copy_slice(allocator, st.as_bytes())?;

    Some(unsafe {
        // SAFETY: this is a copy of `st` which is valid utf-8
        core::str::from_utf8_unchecked(bytes)
    })
}
