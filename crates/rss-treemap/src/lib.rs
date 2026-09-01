//! Squarified treemap layout — pure geometry, zero dependencies (SPEC.md §6.2).
//!
//! Implements the classic squarified treemap algorithm of Bruls, Huizing and
//! van Wijk ("Squarified Treemaps", 1999,
//! <https://www.win.tue.nl/~vanwijk/stm.pdf>): items are greedily grouped into
//! rows laid along the shortest remaining side so that cell aspect ratios stay
//! close to 1, which is what makes sizes comparable by eye.
//!
//! Contract (FR-3.1 / FR-3.2):
//! - Output rectangle areas are strictly proportional to input weights.
//! - There is **no minimum cell size** — culling of sub-pixel cells is the
//!   renderer's job (SPEC.md §5.3). Zero-weight items occupy zero area and are
//!   excluded from the output entirely.
//! - Empty input yields empty output; degenerate containers (zero/negative or
//!   non-finite width/height) yield empty output instead of panicking or
//!   producing NaN.
//!
//! Two ordering modes are supported ([`Order`]): [`Order::Sorted`] for best
//! aspect ratios, and [`Order::StableOrder`] which preserves input order and is
//! used during progressive scans to avoid the "boiling treemap" effect
//! (FR-3.16).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::cmp::Ordering;

/// An axis-aligned rectangle in f32 canvas coordinates.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rect {
    /// Left edge.
    pub x: f32,
    /// Top edge.
    pub y: f32,
    /// Width (extent along +x).
    pub w: f32,
    /// Height (extent along +y).
    pub h: f32,
}

impl Rect {
    /// Creates a rectangle from its origin and size.
    pub const fn new(x: f32, y: f32, w: f32, h: f32) -> Self {
        Self { x, y, w, h }
    }

    /// Area (`w * h`).
    pub fn area(&self) -> f32 {
        self.w * self.h
    }

    /// Right edge (`x + w`).
    pub fn right(&self) -> f32 {
        self.x + self.w
    }

    /// Bottom edge (`y + h`).
    pub fn bottom(&self) -> f32 {
        self.y + self.h
    }
}

/// Item ordering used by [`layout`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Order {
    /// Items are laid out in descending weight order. This is the classic
    /// squarified input precondition and gives the best aspect ratios
    /// ("big items top-left", FR-3.15).
    #[default]
    Sorted,
    /// Input order is preserved. Use this while a scan is in progress so that
    /// throttled re-layouts do not reshuffle cells between ticks (the
    /// "boiling treemap" effect, FR-3.16). Aspect ratios degrade gracefully.
    StableOrder,
}

/// One input element for [`layout`]: a caller-provided id plus a positive
/// weight (typically a byte count). Weights are `f64` so that large sizes
/// (up to 2^53 bytes) are represented exactly.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Item<T> {
    /// Opaque caller-provided identifier, echoed back in [`Placed::id`].
    pub id: T,
    /// Element weight; must be finite and `> 0` to appear in the output.
    pub weight: f64,
}

/// An input element with its computed rectangle.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Placed<T> {
    /// The id of the source [`Item`].
    pub id: T,
    /// The rectangle assigned to this element, inside the container.
    pub rect: Rect,
}

/// Lays out `items` inside `container` with the squarified treemap algorithm.
///
/// Returns one [`Placed`] rectangle per item with a finite weight `> 0`, in
/// layout order (which for [`Order::StableOrder`] equals the input order).
/// Areas are strictly proportional to weights; their sum equals the container
/// area up to float rounding.
///
/// Returns an empty vector when there are no usable items or when the
/// container is degenerate (non-finite, or `w <= 0` / `h <= 0`).
pub fn layout<T: Copy>(container: Rect, items: &[Item<T>], order: Order) -> Vec<Placed<T>> {
    if !container.x.is_finite()
        || !container.y.is_finite()
        || !container.w.is_finite()
        || !container.h.is_finite()
        || container.w <= 0.0
        || container.h <= 0.0
    {
        return Vec::new();
    }

    // Indices of usable items, in processing order.
    let mut order_idx: Vec<usize> = (0..items.len())
        .filter(|&i| items[i].weight.is_finite() && items[i].weight > 0.0)
        .collect();
    if order_idx.is_empty() {
        return Vec::new();
    }
    if order == Order::Sorted {
        // Stable sort: descending weight, input order breaks ties.
        order_idx.sort_by(|&a, &b| {
            items[b]
                .weight
                .partial_cmp(&items[a].weight)
                .unwrap_or(Ordering::Equal)
        });
    }

    // Normalize weights so their sum equals the container area (FR-3.1).
    let total: f64 = order_idx.iter().map(|&i| items[i].weight).sum();
    let area = f64::from(container.w) * f64::from(container.h);
    let scale = area / total;
    let weights: Vec<f64> = order_idx.iter().map(|&i| items[i].weight * scale).collect();

    let container64 = F64Rect {
        x: f64::from(container.x),
        y: f64::from(container.y),
        w: f64::from(container.w),
        h: f64::from(container.h),
    };
    let mut rects = vec![F64Rect::ZERO; weights.len()];
    squarify(&weights, container64, &mut rects);

    order_idx
        .into_iter()
        .zip(rects)
        .map(|(i, r)| Placed {
            id: items[i].id,
            rect: r.to_f32(),
        })
        .collect()
}

/// Internal f64 rectangle: layout math is done in f64 for precision and
/// converted to f32 only at the output boundary.
#[derive(Debug, Clone, Copy)]
struct F64Rect {
    x: f64,
    y: f64,
    w: f64,
    h: f64,
}

impl F64Rect {
    const ZERO: Self = Self {
        x: 0.0,
        y: 0.0,
        w: 0.0,
        h: 0.0,
    };

    fn to_f32(self) -> Rect {
        Rect {
            x: self.x as f32,
            y: self.y as f32,
            w: self.w as f32,
            h: self.h as f32,
        }
    }
}

/// Core squarify loop. `weights` are normalized (sum == `rect` area) and in
/// processing order; `out[i]` receives the rectangle for `weights[i]`.
fn squarify(weights: &[f64], mut rect: F64Rect, out: &mut [F64Rect]) {
    debug_assert_eq!(weights.len(), out.len());

    // weights[row_begin..next) is the row currently being accumulated.
    let mut row_begin = 0usize;
    let mut next = 0usize;
    while next < weights.len() {
        let side = rect.w.min(rect.h);
        let row = &weights[row_begin..next];
        let candidate = &weights[row_begin..=next];
        // Grow the row while doing so does not worsen its worst aspect ratio.
        if row.is_empty() || side <= 0.0 || worst(candidate, side) <= worst(row, side) {
            next += 1;
        } else {
            layout_row(row, &mut rect, &mut out[row_begin..next]);
            row_begin = next;
        }
    }
    if row_begin < weights.len() {
        let row = &weights[row_begin..];
        layout_row(row, &mut rect, &mut out[row_begin..]);
    }
}

/// Worst (highest) aspect ratio of `row` when laid along a side of length
/// `side`: `max(side^2 * r_max / s^2, s^2 / (side^2 * r_min))` with `s` the
/// row sum. Lower is better; 1.0 is a perfect square.
fn worst(row: &[f64], side: f64) -> f64 {
    let mut sum = 0.0;
    let mut min = f64::INFINITY;
    let mut max = 0.0_f64;
    for &r in row {
        sum += r;
        if r < min {
            min = r;
        }
        if r > max {
            max = r;
        }
    }
    let sum2 = sum * sum;
    let side2 = side * side;
    (side2 * max / sum2).max(sum2 / (side2 * min))
}

/// Lays out one row inside `rect` and shrinks `rect` to the remaining space.
/// The row occupies a strip along the shortest side: a vertical strip on the
/// left when the rect is wider than tall, a horizontal strip on top otherwise.
fn layout_row(row: &[f64], rect: &mut F64Rect, out: &mut [F64Rect]) {
    debug_assert_eq!(row.len(), out.len());
    let sum: f64 = row.iter().sum();
    // Paranoia guard against float drift on pathological inputs: never emit
    // non-finite or negative geometry.
    if sum <= 0.0 || rect.w <= 0.0 || rect.h <= 0.0 {
        out.iter_mut().for_each(|o| *o = F64Rect::ZERO);
        return;
    }

    if rect.w >= rect.h {
        let strip_w = sum / rect.h;
        let mut y = rect.y;
        for (&r, o) in row.iter().zip(out.iter_mut()) {
            let h = r / strip_w;
            *o = F64Rect {
                x: rect.x,
                y,
                w: strip_w,
                h,
            };
            y += h;
        }
        rect.x += strip_w;
        rect.w -= strip_w;
    } else {
        let strip_h = sum / rect.w;
        let mut x = rect.x;
        for (&r, o) in row.iter().zip(out.iter_mut()) {
            let w = r / strip_h;
            *o = F64Rect {
                x,
                y: rect.y,
                w,
                h: strip_h,
            };
            x += w;
        }
        rect.y += strip_h;
        rect.h -= strip_h;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPS: f32 = 1e-4;

    fn approx(a: f32, b: f32) -> bool {
        (a - b).abs() <= EPS * b.abs().max(1.0)
    }

    fn assert_rect_approx(actual: Rect, expected: Rect) {
        assert!(
            approx(actual.x, expected.x)
                && approx(actual.y, expected.y)
                && approx(actual.w, expected.w)
                && approx(actual.h, expected.h),
            "rect mismatch: got {actual:?}, expected {expected:?}"
        );
    }

    fn items(weights: &[f64]) -> Vec<Item<usize>> {
        weights
            .iter()
            .enumerate()
            .map(|(i, &weight)| Item { id: i, weight })
            .collect()
    }

    /// Intersection area of two rects (0 when they only touch).
    fn intersection_area(a: Rect, b: Rect) -> f32 {
        let w = (a.right().min(b.right()) - a.x.max(b.x)).max(0.0);
        let h = (a.bottom().min(b.bottom()) - a.y.max(b.y)).max(0.0);
        w * h
    }

    /// Shared geometric invariants: area conservation, containment, no overlap.
    fn check_invariants(container: Rect, placed: &[Placed<usize>]) {
        let container_area = container.area();
        let total: f32 = placed.iter().map(|p| p.rect.area()).sum();
        assert!(
            (total - container_area).abs() <= 1e-3 * container_area.max(1.0),
            "area not conserved: {total} vs {container_area}"
        );
        for (i, p) in placed.iter().enumerate() {
            let r = p.rect;
            assert!(
                r.x.is_finite() && r.y.is_finite() && r.w.is_finite() && r.h.is_finite(),
                "non-finite rect {r:?}"
            );
            assert!(r.w > 0.0 && r.h > 0.0, "non-positive rect {r:?}");
            assert!(
                r.x >= container.x - EPS
                    && r.y >= container.y - EPS
                    && r.right() <= container.right() + EPS
                    && r.bottom() <= container.bottom() + EPS,
                "rect {r:?} escapes container {container:?}"
            );
            for q in &placed[i + 1..] {
                let overlap = intersection_area(r, q.rect);
                assert!(
                    overlap <= 1e-4 * container_area.max(1.0),
                    "rects overlap by {overlap}: {r:?} vs {:?}",
                    q.rect
                );
            }
        }
    }

    /// Golden test: the worked example from "Squarified Treemaps"
    /// (Bruls, Huizing, van Wijk, 1999): weights 6, 6, 4, 3, 2, 2, 1 in a
    /// 6 x 4 container. Rows are [6,6] (left strip), [4,3] (top strip of the
    /// remainder), then [2], [2], [1] as horizontal strips on the right.
    /// Expected coordinates are exact fractions, computed by hand.
    #[test]
    fn golden_paper_example() {
        let container = Rect::new(0.0, 0.0, 6.0, 4.0);
        let placed = layout(
            container,
            &items(&[6.0, 6.0, 4.0, 3.0, 2.0, 2.0, 1.0]),
            Order::Sorted,
        );
        assert_eq!(placed.len(), 7);

        let f = |num: f64, den: f64| (num / den) as f32;
        let expected = [
            Rect::new(0.0, 0.0, 3.0, 2.0),
            Rect::new(0.0, 2.0, 3.0, 2.0),
            Rect::new(3.0, 0.0, f(12.0, 7.0), f(7.0, 3.0)),
            Rect::new(f(33.0, 7.0), 0.0, f(9.0, 7.0), f(7.0, 3.0)),
            Rect::new(3.0, f(7.0, 3.0), 1.2, f(5.0, 3.0)),
            Rect::new(4.2, f(7.0, 3.0), 1.2, f(5.0, 3.0)),
            Rect::new(5.4, f(7.0, 3.0), 0.6, f(5.0, 3.0)),
        ];
        // Already sorted, so output order is input order.
        for (p, &e) in placed.iter().zip(expected.iter()) {
            assert_rect_approx(p.rect, e);
        }
        check_invariants(container, &placed);

        // Squarified sanity: worst aspect ratio stays moderate.
        let worst_aspect = placed
            .iter()
            .map(|p| {
                let (a, b) = (p.rect.w.max(p.rect.h), p.rect.w.min(p.rect.h));
                a / b
            })
            .fold(1.0_f32, f32::max);
        assert!(worst_aspect < 3.0, "worst aspect ratio {worst_aspect}");
    }

    #[test]
    fn strict_proportionality() {
        let container = Rect::new(0.0, 0.0, 800.0, 600.0);
        let weights = [100.0, 55.0, 33.0, 21.0, 13.0, 8.0, 5.0, 3.0, 2.0, 1.0];
        let placed = layout(container, &items(&weights), Order::Sorted);
        for a in &placed {
            for b in &placed {
                let wa = weights[a.id];
                let wb = weights[b.id];
                let ratio_rects = f64::from(a.rect.area()) / f64::from(b.rect.area());
                let ratio_weights = wa / wb;
                assert!(
                    (ratio_rects / ratio_weights - 1.0).abs() < 1e-3,
                    "areas not proportional: {a:?} vs {b:?}"
                );
            }
        }
    }

    #[test]
    fn sorted_mode_outputs_descending_weight() {
        let container = Rect::new(0.0, 0.0, 100.0, 100.0);
        let input = items(&[1.0, 9.0, 4.0, 16.0, 25.0]);
        let placed = layout(container, &input, Order::Sorted);
        let out_weights: Vec<f64> = placed.iter().map(|p| input[p.id].weight).collect();
        assert_eq!(out_weights, vec![25.0, 16.0, 9.0, 4.0, 1.0]);
        check_invariants(container, &placed);
    }

    #[test]
    fn stable_order_preserves_input_order() {
        let container = Rect::new(0.0, 0.0, 100.0, 100.0);
        let input = items(&[1.0, 9.0, 4.0, 16.0, 25.0]);
        let placed = layout(container, &input, Order::StableOrder);
        let ids: Vec<usize> = placed.iter().map(|p| p.id).collect();
        assert_eq!(ids, vec![0, 1, 2, 3, 4]);
        check_invariants(container, &placed);
    }

    /// FR-3.16: with stable ordering, monotonically growing weights across
    /// progressive-scan ticks never reshuffle the relative item order.
    #[test]
    fn stable_order_is_stable_across_ticks() {
        let container = Rect::new(0.0, 0.0, 640.0, 480.0);
        let base = [3.0, 30.0, 7.0, 12.0, 1.0, 20.0, 5.0];
        let mut previous: Option<Vec<usize>> = None;
        for tick in 1..=8u32 {
            let input = items(&base.map(|w| w * f64::from(tick)));
            let placed = layout(container, &input, Order::StableOrder);
            let ids: Vec<usize> = placed.iter().map(|p| p.id).collect();
            assert_eq!(ids, (0..base.len()).collect::<Vec<_>>());
            if let Some(prev) = &previous {
                assert_eq!(&ids, prev, "order changed between ticks");
            }
            previous = Some(ids);
            check_invariants(container, &placed);
        }
    }

    #[test]
    fn zero_weight_items_are_excluded() {
        let container = Rect::new(0.0, 0.0, 100.0, 100.0);
        let input = items(&[0.0, 5.0, 0.0, 5.0]);
        let placed = layout(container, &input, Order::Sorted);
        let ids: Vec<usize> = placed.iter().map(|p| p.id).collect();
        assert_eq!(ids, vec![1, 3]);
        check_invariants(container, &placed);
    }

    #[test]
    fn empty_input_yields_empty_output() {
        let container = Rect::new(0.0, 0.0, 100.0, 100.0);
        assert!(layout::<usize>(container, &[], Order::Sorted).is_empty());
        assert!(layout::<usize>(container, &[], Order::StableOrder).is_empty());
    }

    #[test]
    fn degenerate_containers_do_not_panic_or_nan() {
        let input = items(&[1.0, 2.0, 3.0]);
        for container in [
            Rect::new(0.0, 0.0, 0.0, 0.0),
            Rect::new(0.0, 0.0, 0.0, 10.0),
            Rect::new(0.0, 0.0, 10.0, 0.0),
            Rect::new(0.0, 0.0, -5.0, 10.0),
            Rect::new(0.0, 0.0, f32::NAN, 10.0),
            Rect::new(0.0, 0.0, 10.0, f32::INFINITY),
        ] {
            assert!(
                layout(container, &input, Order::Sorted).is_empty(),
                "container {container:?} should yield no output"
            );
        }
    }

    #[test]
    fn non_finite_weights_are_excluded() {
        let container = Rect::new(0.0, 0.0, 100.0, 100.0);
        let input = items(&[f64::NAN, 4.0, f64::INFINITY, 1.0]);
        let placed = layout(container, &input, Order::Sorted);
        let ids: Vec<usize> = placed.iter().map(|p| p.id).collect();
        assert_eq!(ids, vec![1, 3]);
        check_invariants(container, &placed);
    }

    #[test]
    fn single_item_fills_container() {
        let container = Rect::new(10.0, 20.0, 300.0, 200.0);
        let placed = layout(container, &items(&[42.0]), Order::Sorted);
        assert_eq!(placed.len(), 1);
        assert_rect_approx(placed[0].rect, container);
    }

    /// Deterministic LCG so property tests need no external crates.
    struct Lcg(u64);

    impl Lcg {
        fn next_f64(&mut self) -> f64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 11) as f64 / (1u64 << 53) as f64
        }
    }

    #[test]
    fn property_random_inputs() {
        let mut rng = Lcg(0x5EED);
        for case in 0..20 {
            let n = 1 + (rng.next_f64() * 199.0) as usize;
            let weights: Vec<f64> = (0..n).map(|_| 0.01 + rng.next_f64() * 1e6).collect();
            let container = Rect::new(
                rng.next_f64() as f32 * 10.0,
                rng.next_f64() as f32 * 10.0,
                1.0 + rng.next_f64() as f32 * 2000.0,
                1.0 + rng.next_f64() as f32 * 2000.0,
            );
            let input = items(&weights);
            for order in [Order::Sorted, Order::StableOrder] {
                let placed = layout(container, &input, order);
                assert_eq!(placed.len(), n, "case {case}, order {order:?}");
                check_invariants(container, &placed);
            }
        }
    }

    /// Smoke test: 10k items must lay out quickly and sanely (SPEC.md §8
    /// budget: sub-millisecond at hundreds of cells; 10k is headroom).
    #[test]
    fn smoke_10k_items() {
        let mut rng = Lcg(0xC0FFEE);
        let weights: Vec<f64> = (0..10_000).map(|_| 0.5 + rng.next_f64() * 1e4).collect();
        let container = Rect::new(0.0, 0.0, 1920.0, 1080.0);
        let input = items(&weights);

        let start = std::time::Instant::now();
        let placed = layout(container, &input, Order::Sorted);
        let elapsed = start.elapsed();

        assert_eq!(placed.len(), 10_000);
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "10k layout took {elapsed:?}"
        );
        let total: f64 = placed.iter().map(|p| f64::from(p.rect.area())).sum();
        let expected = f64::from(container.area());
        assert!(
            (total / expected - 1.0).abs() < 1e-3,
            "area drift: {total} vs {expected}"
        );
        for p in &placed {
            let r = p.rect;
            assert!(
                r.x.is_finite()
                    && r.y.is_finite()
                    && r.w > 0.0
                    && r.h > 0.0
                    && r.x >= -EPS
                    && r.y >= -EPS
                    && r.right() <= container.w + EPS
                    && r.bottom() <= container.h + EPS,
                "bad rect {r:?}"
            );
        }
    }
}
