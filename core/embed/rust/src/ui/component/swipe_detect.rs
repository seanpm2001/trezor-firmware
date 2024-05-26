use crate::{
    time::{Duration, Instant},
    ui::{
        animation::Animation,
        component::{Event, EventCtx, SwipeDirection},
        event::TouchEvent,
        geometry::{Offset, Point},
        util::animation_disabled,
    },
};

#[derive(Clone)]
pub struct SwipeSettings {
    pub duration: Duration,
}

impl SwipeSettings {
    pub const fn new(duration: Duration) -> Self {
        Self { duration }
    }

    pub const fn default() -> Self {
        Self {
            duration: Duration::from_millis(333),
        }
    }

    pub const fn immediate() -> Self {
        Self {
            duration: Duration::from_millis(0),
        }
    }
}

#[derive(Clone, Default)]
pub struct SwipeConfig {
    pub horizontal_pages: bool,
    pub vertical_pages: bool,
    pub up: Option<SwipeSettings>,
    pub down: Option<SwipeSettings>,
    pub left: Option<SwipeSettings>,
    pub right: Option<SwipeSettings>,
}

impl SwipeConfig {
    pub const fn new() -> Self {
        Self {
            horizontal_pages: false,
            vertical_pages: false,
            up: None,
            down: None,
            left: None,
            right: None,
        }
    }

    pub fn with_swipe(&self, dir: SwipeDirection, settings: SwipeSettings) -> Self {
        let mut new = self.clone();
        match dir {
            SwipeDirection::Up => new.up = Some(settings),
            SwipeDirection::Down => new.down = Some(settings),
            SwipeDirection::Left => new.left = Some(settings),
            SwipeDirection::Right => new.right = Some(settings),
        }
        new
    }

    pub fn is_allowed(&self, dir: SwipeDirection) -> bool {
        match dir {
            SwipeDirection::Up => self.up.is_some(),
            SwipeDirection::Down => self.down.is_some(),
            SwipeDirection::Left => self.left.is_some(),
            SwipeDirection::Right => self.right.is_some(),
        }
    }

    pub fn duration(&self, dir: SwipeDirection) -> Option<Duration> {
        match dir {
            SwipeDirection::Up => self.up.as_ref().map(|s| s.duration),
            SwipeDirection::Down => self.down.as_ref().map(|s| s.duration),
            SwipeDirection::Left => self.left.as_ref().map(|s| s.duration),
            SwipeDirection::Right => self.right.as_ref().map(|s| s.duration),
        }
    }
    pub fn has_horizontal_pages(&self) -> bool {
        self.horizontal_pages
    }

    pub fn has_vertical_pages(&self) -> bool {
        self.vertical_pages
    }

    pub fn with_horizontal_pages(&self) -> Self {
        let mut new = self.clone();
        new.horizontal_pages = true;
        new
    }

    pub fn with_vertical_pages(&self) -> Self {
        let mut new = self.clone();
        new.vertical_pages = true;
        new
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum SwipeDetectMsg {
    Move(SwipeDirection, i16),
    Trigger(SwipeDirection),
}

#[derive(Clone)]
pub struct SwipeDetect {
    origin: Option<Point>,
    locked: Option<SwipeDirection>,
    final_animation: Option<Animation<i16>>,
    moved: i16,
}

impl SwipeDetect {
    const DISTANCE: i16 = 120;
    pub const PROGRESS_MAX: i16 = 1000;

    const DURATION_MS: u32 = 333;
    const TRIGGER_THRESHOLD: f32 = 0.3;
    const DETECT_THRESHOLD: f32 = 0.1;

    pub fn new() -> Self {
        Self {
            origin: None,
            locked: None,
            final_animation: None,
            moved: 0,
        }
    }

    fn min_lock(&self) -> i16 {
        (Self::DISTANCE as f32 * Self::DETECT_THRESHOLD) as i16
    }

    fn min_trigger(&self) -> i16 {
        (Self::DISTANCE as f32 * Self::TRIGGER_THRESHOLD) as i16
    }

    fn progress(&self, val: i16) -> i16 {
        ((val.max(0) as f32 / Self::DISTANCE as f32) * Self::PROGRESS_MAX as f32) as i16
    }

    pub fn trigger(&mut self, ctx: &mut EventCtx, dir: SwipeDirection, config: SwipeConfig) {
        ctx.request_anim_frame();
        ctx.request_paint();

        let duration = config
            .duration(dir)
            .unwrap_or(Duration::from_millis(Self::DURATION_MS));

        self.locked = Some(dir);
        self.final_animation = Some(Animation::new(
            0,
            Self::PROGRESS_MAX,
            duration,
            Instant::now(),
        ));
    }

    pub(crate) fn reset(&mut self) {
        self.origin = None;
        self.locked = None;
        self.final_animation = None;
        self.moved = 0;
    }

    pub(crate) fn event(
        &mut self,
        ctx: &mut EventCtx,
        event: Event,
        config: SwipeConfig,
    ) -> Option<SwipeDetectMsg> {
        match (event, self.origin) {
            (Event::Touch(TouchEvent::TouchStart(pos)), _) => {
                // Mark the starting position of this touch.
                self.origin.replace(pos);
            }
            (Event::Touch(TouchEvent::TouchMove(pos)), Some(origin)) => {
                if self.final_animation.is_none() {
                    // Compare the touch distance with our allowed directions and determine if it
                    // constitutes a valid swipe.
                    let ofs = pos - origin;
                    let ofs_min = ofs.abs() - Offset::new(self.min_lock(), self.min_lock());

                    let mut res = None;
                    if self.locked.is_none() {
                        if ofs.x > 0 && ofs_min.x > 0 && config.is_allowed(SwipeDirection::Right) {
                            self.locked = Some(SwipeDirection::Right);
                            res = Some(SwipeDetectMsg::Move(
                                SwipeDirection::Right,
                                self.progress(ofs_min.x),
                            ));
                        }
                        if ofs.x < 0 && ofs_min.x > 0 && config.is_allowed(SwipeDirection::Left) {
                            self.locked = Some(SwipeDirection::Left);
                            res = Some(SwipeDetectMsg::Move(
                                SwipeDirection::Left,
                                self.progress(ofs_min.x),
                            ));
                        }
                        if ofs.y < 0 && ofs_min.y > 0 && config.is_allowed(SwipeDirection::Up) {
                            self.locked = Some(SwipeDirection::Up);
                            res = Some(SwipeDetectMsg::Move(
                                SwipeDirection::Up,
                                self.progress(ofs_min.y),
                            ));
                        }
                        if ofs.y > 0 && ofs_min.y > 0 && config.is_allowed(SwipeDirection::Down) {
                            self.locked = Some(SwipeDirection::Down);
                            res = Some(SwipeDetectMsg::Move(
                                SwipeDirection::Down,
                                self.progress(ofs_min.y),
                            ));
                        }
                    } else {
                        res = match self.locked.unwrap() {
                            SwipeDirection::Left => {
                                if ofs.x > 0 {
                                    Some(SwipeDetectMsg::Move(SwipeDirection::Left, 0))
                                } else {
                                    Some(SwipeDetectMsg::Move(
                                        SwipeDirection::Left,
                                        self.progress(ofs_min.x),
                                    ))
                                }
                            }
                            SwipeDirection::Right => {
                                if ofs.x < 0 {
                                    Some(SwipeDetectMsg::Move(SwipeDirection::Right, 0))
                                } else {
                                    Some(SwipeDetectMsg::Move(
                                        SwipeDirection::Right,
                                        self.progress(ofs_min.x),
                                    ))
                                }
                            }
                            SwipeDirection::Up => {
                                if ofs.y > 0 {
                                    Some(SwipeDetectMsg::Move(SwipeDirection::Up, 0))
                                } else {
                                    Some(SwipeDetectMsg::Move(
                                        SwipeDirection::Up,
                                        self.progress(ofs_min.y),
                                    ))
                                }
                            }
                            SwipeDirection::Down => {
                                if ofs.y < 0 {
                                    Some(SwipeDetectMsg::Move(SwipeDirection::Down, 0))
                                } else {
                                    Some(SwipeDetectMsg::Move(
                                        SwipeDirection::Down,
                                        self.progress(ofs_min.y),
                                    ))
                                }
                            }
                        };
                    }

                    // Todo trigger an action if distance is met

                    if let Some(SwipeDetectMsg::Move(_, ofs)) = res {
                        self.moved = ofs;
                    }

                    if animation_disabled() {
                        return None;
                    }

                    return res;
                }
            }
            (Event::Touch(TouchEvent::TouchEnd(pos)), Some(origin)) => {
                if self.final_animation.is_none() {
                    // Touch interaction is over, reset the position.
                    self.origin.take();

                    // Compare the touch distance with our allowed directions and determine if it
                    // constitutes a valid swipe.
                    let ofs = pos - origin;
                    let ofs_min = ofs.abs() - Offset::new(self.min_trigger(), self.min_trigger());

                    let mut final_value = 0;
                    let mut finalize = false;
                    if self.locked.is_none() {
                        if ofs.x > 0 && ofs_min.x > 0 && config.is_allowed(SwipeDirection::Right) {
                            final_value = Self::PROGRESS_MAX;
                            finalize = true;
                            self.locked = Some(SwipeDirection::Right);
                        }
                        if ofs.x < 0 && ofs_min.x > 0 && config.is_allowed(SwipeDirection::Left) {
                            final_value = Self::PROGRESS_MAX;
                            finalize = true;
                            self.locked = Some(SwipeDirection::Left);
                        }
                        if ofs.y < 0 && ofs_min.y > 0 && config.is_allowed(SwipeDirection::Up) {
                            final_value = Self::PROGRESS_MAX;
                            finalize = true;
                            self.locked = Some(SwipeDirection::Up);
                        }
                        if ofs.y > 0 && ofs_min.y > 0 && config.is_allowed(SwipeDirection::Down) {
                            final_value = Self::PROGRESS_MAX;
                            finalize = true;
                            self.locked = Some(SwipeDirection::Down);
                        }
                    } else {
                        let locked = self.locked.unwrap();
                        finalize = true;

                        match locked {
                            SwipeDirection::Right => {
                                if ofs.x > 0 && ofs_min.x > 0 {
                                    final_value = Self::PROGRESS_MAX;
                                }
                            }
                            SwipeDirection::Left => {
                                if ofs.x < 0 && ofs_min.x > 0 {
                                    final_value = Self::PROGRESS_MAX;
                                }
                            }
                            SwipeDirection::Up => {
                                if ofs.y < 0 && ofs_min.y > 0 {
                                    final_value = Self::PROGRESS_MAX;
                                }
                            }
                            SwipeDirection::Down => {
                                if ofs.y > 0 && ofs_min.y > 0 {
                                    final_value = Self::PROGRESS_MAX;
                                }
                            }
                        };
                    }

                    if finalize {
                        if !animation_disabled() {
                            ctx.request_anim_frame();
                            ctx.request_paint();

                            let done = self.moved as f32 / Self::PROGRESS_MAX as f32;
                            let ratio = 1.0 - done;

                            let duration = config
                                .duration(self.locked.unwrap())
                                .unwrap_or(Duration::from_millis(Self::DURATION_MS));

                            let duration = ((duration.to_millis() as f32 * ratio) as u32).max(0);
                            self.final_animation = Some(Animation::new(
                                self.moved,
                                final_value,
                                Duration::from_millis(duration),
                                Instant::now(),
                            ));
                        } else {
                            ctx.request_anim_frame();
                            ctx.request_paint();
                            self.final_animation = None;
                            self.moved = 0;
                            let locked = self.locked.take();
                            if final_value != 0 {
                                return Some(SwipeDetectMsg::Trigger(locked.unwrap()));
                            }
                        }
                    }

                    return None;
                }
            }
            (Event::Timer(EventCtx::ANIM_FRAME_TIMER), _) => {
                if self.locked.is_some() {
                    let mut finish = false;
                    let res = if let Some(animation) = &self.final_animation {
                        if animation.finished(Instant::now()) {
                            finish = true;
                            if animation.to != 0 {
                                Some(SwipeDetectMsg::Trigger(self.locked.unwrap()))
                            } else {
                                Some(SwipeDetectMsg::Move(self.locked.unwrap(), 0))
                            }
                        } else {
                            ctx.request_anim_frame();
                            ctx.request_paint();
                            if animation_disabled() {
                                None
                            } else {
                                Some(SwipeDetectMsg::Move(
                                    self.locked.unwrap(),
                                    animation.value(Instant::now()),
                                ))
                            }
                        }
                    } else {
                        None
                    };

                    if finish {
                        self.locked = None;
                        ctx.request_anim_frame();
                        ctx.request_paint();
                        self.final_animation = None;
                        self.moved = 0;
                    }

                    return res;
                }
            }
            _ => {
                // Do nothing.
            }
        }
        None
    }
}
