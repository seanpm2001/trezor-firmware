use crate::ui::geometry::Rect;

use super::{base::SimpleClone, Canvas, DrawingCache, Renderer, Shape};

#[derive(Clone)]
pub struct Blurring {
    // Blurred area
    area: Rect,
    /// Blurring kernel radius
    radius: usize,
}

/// A shape for the blurring of a specified rectangle area.
impl Blurring {
    pub fn new(area: Rect, radius: usize) -> Self {
        Self { area, radius }
    }

    pub fn render<'s>(mut self, renderer: &mut impl Renderer<'s>) {
        renderer.render_shape(&mut self);
    }
}

impl Shape<'_> for Blurring {
    fn bounds(&self, _cache: &DrawingCache) -> Rect {
        self.area
    }

    fn cleanup(&mut self, _cache: &DrawingCache) {}

    fn draw(&mut self, canvas: &mut dyn Canvas, cache: &DrawingCache) {
        canvas.blur_rect(self.area, self.radius, cache);
    }
}

impl SimpleClone for Blurring {}
