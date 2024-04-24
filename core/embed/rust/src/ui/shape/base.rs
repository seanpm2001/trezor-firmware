use crate::ui::geometry::Rect;

use super::{alloc_utils::alloc_t, Canvas, DrawingCache};

use alloc_traits::LocalAlloc;

// ==========================================================================
// trait Shape
// ==========================================================================

/// This trait is used internally by so-called Renderers -
/// `DirectRenderer` & `ProgressiveRederer`.
///
/// All shapes (like `Bar`, `Text`, `Circle`, ...) that can be rendered
/// must implement `Shape` trait.
///
/// `Shape` objects may use `DrawingCache` as a scratch-pad memory or for
/// caching expensive calculations results.
pub trait Shape<'cache> {
    /// Returns the smallest bounding rectangle containing whole parts of the
    /// shape.
    ///
    /// The function is used by renderer for optimization if the shape
    /// must be renderer or not.
    fn bounds(&self, cache: &DrawingCache<'cache>) -> Rect;

    /// Draws shape on the canvas.
    fn draw(&mut self, canvas: &mut dyn Canvas, cache: &DrawingCache<'cache>);

    /// The function should release all allocated resources needed
    /// for shape drawing.
    ///
    /// It's called by renderer if the shape's draw() function won't be called
    /// anymore.
    fn cleanup(&mut self, cache: &DrawingCache<'cache>);
}

// ==========================================================================
// trait ShapeClone
// ==========================================================================

/// All shapes (like `Bar`, `Text`, `Circle`, ...) that can be rendered
/// by `ProgressiveRender` must implement `ShapeClone`.
pub trait ShapeClone<'cache>: Shape<'cache> {
    /// Clones a shape object at the specified memory bump.
    ///
    /// The method is used by `ProgressiveRenderer` to store shape objects for
    /// deferred drawing.
    fn clone_at_bump(
        &self,
        allocator: &'cache dyn LocalAlloc<'cache>,
    ) -> Option<&'cache mut dyn Shape<'cache>>;
}

pub trait SimpleClone: Clone {}

impl<'cache, T> ShapeClone<'cache> for T
where
    T: Shape<'cache> + 'cache + SimpleClone,
{
    fn clone_at_bump(
        &self,
        allocator: &'cache dyn LocalAlloc<'cache>,
    ) -> Option<&'cache mut dyn Shape<'cache>> {
        let clone = alloc_t(allocator)?;
        Some(clone.uninit.init(self.clone()))
    }
}
