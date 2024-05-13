use super::ffi;

use crate::ui::{
    display::Color,
    geometry::Rect,
    shape::{Bitmap, BitmapFormat, BitmapView},
};

/// Waits for the DMA2D peripheral transfer to complete.
pub fn wait_for_transfer() {
    // SAFETY:
    // `ffi::dma2d_wait()` is always safe to call.
    #[cfg(feature = "dma2d")]
    unsafe {
        ffi::dma2d_wait()
    }
}

impl Default for ffi::gfx_bitblt_t {
    fn default() -> Self {
        Self {
            width: 0,
            height: 0,
            dst_row: core::ptr::null_mut(),
            dst_stride: 0,
            dst_x: 0,
            dst_y: 0,
            src_row: core::ptr::null_mut(),
            src_bg: 0,
            src_fg: 0,
            src_stride: 0,
            src_x: 0,
            src_y: 0,
            src_alpha: 255,
        }
    }
}

impl ffi::gfx_bitblt_t {
    /// Sets the destination bitmap.
    ///
    /// Be sure that clipping rectangle specified in the `new_fill()` or
    /// `new_copy()` method is completely inside the destination bitmap.
    fn with_dst(self, dst: &mut Bitmap) -> Self {
        // Ensure that the destination rectangle is completely inside the
        // destination bitmap.
        assert!(dst.width() as u16 >= self.dst_x + self.width);
        assert!(dst.height() as u16 >= self.dst_y + self.height);

        Self {
            // SAFETY:
            // Lines between `dst_y` and`dst_y + height` are inside
            // the destination bitmap.
            dst_row: unsafe { dst.row_ptr(self.dst_y) },
            dst_stride: dst.stride() as u16,
            ..self
        }
    }

    // Sets the destination rectangle.
    fn with_rect(self, r: Rect) -> Self {
        Self {
            width: r.width() as u16,
            height: r.height() as u16,
            dst_x: r.x0 as u16,
            dst_y: r.y0 as u16,
            ..self
        }
    }

    /// Sets the source bitmap
    ///
    /// `x` and `y` specify the offset applied to the source bitmap and
    /// must be inside the source bitmap.
    fn with_src(self, bitmap: &Bitmap, x: i16, y: i16) -> Self {
        let bitmap_stride = match bitmap.format() {
            BitmapFormat::MONO1P => bitmap.width() as u16, // packed bits
            _ => bitmap.stride() as u16,
        };

        Self {
            // SAFETY:
            // it's safe if source rectangle is properly clipped
            // (ensured by the `BitBltCopy::new()`).
            src_row: unsafe { bitmap.row_ptr(y as u16) },
            src_stride: bitmap_stride,
            src_x: x as u16,
            src_y: y as u16,
            ..self
        }
    }

    /// Sets foreground color used for rectangle filling or
    /// drawing monochrome bitmaps.
    fn with_fg(self, fg_color: Color) -> Self {
        Self {
            src_fg: fg_color.into(),
            ..self
        }
    }

    /// Sets foreground color used for drawing monochrome bitmaps.
    fn with_bg(self, bg_color: Color) -> Self {
        Self {
            src_bg: bg_color.into(),
            ..self
        }
    }

    /// Sets the foreground alpha value used for rectangle filling or
    /// bitmap blending.
    fn with_alpha(self, alpha: u8) -> Self {
        Self {
            src_alpha: alpha,
            ..self
        }
    }

    pub unsafe fn fill_op(
        dst: &mut Bitmap,
        r: Rect,
        clip: Rect,
        color: Color,
        alpha: u8,
    ) -> Option<Self> {
        let r = r.clamp(clip);
        if r.is_empty() {
            return None;
        }

        let blt_op = Self::default()
            .with_rect(r)
            .with_fg(color)
            .with_alpha(alpha);

        Some(unsafe { blt_op.with_dst(dst) })
    }

    pub unsafe fn copy_op(dst: &mut Bitmap, src: &BitmapView, r: Rect, clip: Rect) -> Option<Self> {
        let mut offset = src.offset;
        let mut r_dst = r;

        // Normalize negative x & y-offset of the bitmap
        if offset.x < 0 {
            r_dst.x0 -= offset.x;
            offset.x = 0;
        }

        if offset.y < 0 {
            r_dst.y0 -= offset.y;
            offset.y = 0;
        }

        // Clip with the canvas viewport
        let mut r = r_dst.clamp(clip);

        // Clip with the bitmap top-left
        if r.x0 > r_dst.x0 {
            offset.x += r.x0 - r_dst.x0;
        }

        if r.y0 > r_dst.y0 {
            offset.y += r.y0 - r_dst.y0;
        }

        // Clip with the bitmap size
        r.x1 = r.x1.min(r.x0 + src.size().x - offset.x);
        r.y1 = r.y1.min(r.y0 + src.size().y - offset.y);

        if !r.is_empty() {
            Some(
                Self::default()
                    .with_rect(r)
                    .with_src(src.bitmap, offset.x, offset.y)
                    .with_bg(src.bg_color)
                    .with_fg(src.fg_color),
            )
        } else {
            None
        }
    }
}

/// Rectangle filling operation.
pub trait BitBltFill {
    fn bitblt_fill(&mut self, r: Rect, clip: Rect, color: Color, alpha: u8) -> bool;
    #[cfg(feature = "new_rendering")]
    fn display_fill(&mut self, r: Rect, clip: Rect, color: Color, alpha: u8);
}

impl BitBltFill for Bitmap<'_> {
    fn bitblt_fill(&mut self, r: Rect, clip: Rect, color: Color, alpha: u8) -> bool {
        // SAFETY: dropped at the end of function
        let Some(blt_op) = (unsafe { ffi::gfx_bitblt_t::fill_op(self, r, clip, color, alpha) })
        else {
            return false;
        };

        match self.format() {
            BitmapFormat::RGB565 => unsafe { ffi::gfx_rgb565_fill(&blt_op) },
            BitmapFormat::RGBA8888 => unsafe { ffi::gfx_rgba8888_fill(&blt_op) },
            BitmapFormat::MONO8 => unsafe { ffi::gfx_mono8_fill(&blt_op) },
            _ => unimplemented!(),
        }

        self.mark_dma_pending();
        true
    }

    /// Fills a rectangle on the display with the specified color.
    #[cfg(feature = "new_rendering")]
    fn display_fill(&mut self, r: Rect, clip: Rect, color: Color, alpha: u8) {
        let Some(blt_op) = (unsafe { ffi::gfx_bitblt_t::fill_op(self, r, clip, color, alpha) })
        else {
            return;
        };
        unsafe { ffi::display_fill(&blt_op) };
    }
}

pub trait BitBltCopy {
    fn bitblt_copy(&mut self, src: &BitmapView, r: Rect, clip: Rect) -> bool;
    fn bitblt_blend(&mut self, src: &BitmapView, r: Rect, clip: Rect) -> bool;
    #[cfg(feature = "new_rendering")]
    fn display_copy(&mut self, src: &BitmapView, r: Rect, clip: Rect);
}

impl BitBltCopy for Bitmap<'_> {
    fn bitblt_copy(&mut self, src: &BitmapView, r: Rect, clip: Rect) -> bool {
        // SAFETY: dropped at the end of function
        let Some(blt_op) = (unsafe { ffi::gfx_bitblt_t::copy_op(self, src, r, clip) }) else {
            return false;
        };

        match (self.format(), src.format()) {
            (BitmapFormat::MONO8, BitmapFormat::MONO1P) => unsafe {
                ffi::gfx_mono8_copy_mono1p(&blt_op)
            },
            (BitmapFormat::MONO8, BitmapFormat::MONO4) => unsafe {
                ffi::gfx_mono8_copy_mono4(&blt_op)
            },
            (BitmapFormat::RGB565, BitmapFormat::MONO4) => unsafe {
                ffi::gfx_rgb565_copy_mono4(&blt_op)
            },
            (BitmapFormat::RGB565, BitmapFormat::RGB565) => unsafe {
                ffi::gfx_rgb565_copy_rgb565(&blt_op)
            },
            (BitmapFormat::RGBA8888, BitmapFormat::MONO4) => unsafe {
                ffi::gfx_rgba8888_copy_mono4(&blt_op)
            },
            (BitmapFormat::RGBA8888, BitmapFormat::RGB565) => unsafe {
                ffi::gfx_rgba8888_copy_rgb565(&blt_op)
            },
            (BitmapFormat::RGBA8888, BitmapFormat::RGBA8888) => unsafe {
                ffi::gfx_rgba8888_copy_rgba8888(&blt_op)
            },
            _ => unimplemented!(),
        }

        self.mark_dma_pending();
        src.bitmap.mark_dma_pending();
        true
    }

    fn bitblt_blend(&mut self, src: &BitmapView, r: Rect, clip: Rect) -> bool {
        // SAFETY: dropped at the end of function
        let Some(blt_op) = (unsafe { ffi::gfx_bitblt_t::copy_op(self, src, r, clip) }) else {
            return false;
        };

        match (self.format(), src.format()) {
            (BitmapFormat::MONO8, BitmapFormat::MONO1P) => unsafe {
                ffi::gfx_mono8_blend_mono1p(&blt_op)
            },
            (BitmapFormat::MONO8, BitmapFormat::MONO4) => unsafe {
                ffi::gfx_mono8_blend_mono4(&blt_op)
            },
            (BitmapFormat::RGB565, BitmapFormat::MONO4) => unsafe {
                ffi::gfx_rgb565_blend_mono4(&blt_op)
            },
            (BitmapFormat::RGBA8888, BitmapFormat::MONO4) => unsafe {
                ffi::gfx_rgba8888_blend_mono4(&blt_op)
            },
            _ => unimplemented!(),
        }

        self.mark_dma_pending();
        src.bitmap.mark_dma_pending();
        true
    }

    #[cfg(feature = "new_rendering")]
    fn display_copy(&mut self, src: &BitmapView, r: Rect, clip: Rect) {
        let Some(blt_op) = (unsafe { ffi::gfx_bitblt_t::copy_op(self, src, r, clip) }) else {
            return;
        };

        match (self.format(), src.format()) {
            (BitmapFormat::RGB565, BitmapFormat::RGB565) => unsafe {
                ffi::display_copy_rgb565(&blt_op)
            },
            _ => unimplemented!(),
        }

        self.mark_dma_pending();
        src.bitmap.mark_dma_pending();
    }
}
