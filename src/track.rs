//! Heading and range trend from consecutive position fixes (works in `no_std`).
//!
//! A single Location message says where a drone is. Two in a row say where it
//! is going. [`Trajectory`] keeps the last two fixes that were far enough
//! apart to be real motion and turns them into the answers a security operator
//! needs: *which way is it heading*, and *is it coming toward the thing I am
//! guarding or moving away from it*.
//!
//! Fixes closer together than [`MIN_MOVE_M`] are treated as the same point, so
//! a hovering or stationary aircraft does not produce a jittering heading from
//! GNSS noise. Until the aircraft has actually moved, [`Trajectory::heading_deg`]
//! returns `None` rather than a made-up bearing.
//!
//! The bearings and distances come from [`crate::geo`] (great-circle, WGS84).

use crate::geo;

/// Minimum distance in meters between two fixes for the later one to count as
/// movement rather than GNSS jitter.
pub const MIN_MOVE_M: f64 = 3.0;

/// Whether an aircraft is getting closer to a target point or farther from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RangeTrend {
    /// The latest fix is closer to the target than the previous one.
    Closing,
    /// The latest fix is farther from the target than the previous one.
    Opening,
    /// The range changed by less than the dead band: holding its distance.
    Steady,
}

/// Rolling heading and ground track built from consecutive position fixes.
///
/// Feed every plausible fix to [`update`](Self::update); it keeps the latest
/// fix and the last distinct one before it (at least [`MIN_MOVE_M`] away), and
/// derives a heading and range trends from that pair.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Trajectory {
    prev: Option<(f64, f64)>,
    last: Option<(f64, f64)>,
    ground_m: f64,
}

impl Trajectory {
    /// An empty trajectory.
    pub fn new() -> Self {
        Trajectory::default()
    }

    /// Records a fix. Returns the heading in degrees (0 = true north,
    /// clockwise) when this fix is at least [`MIN_MOVE_M`] from the last kept
    /// fix, that is, when the aircraft actually moved; otherwise `None`.
    pub fn update(&mut self, lat: f64, lon: f64) -> Option<f64> {
        match self.last {
            None => {
                self.last = Some((lat, lon));
                None
            }
            Some((plat, plon)) => {
                let d = geo::distance_m(plat, plon, lat, lon);
                if d >= MIN_MOVE_M {
                    self.prev = Some((plat, plon));
                    self.last = Some((lat, lon));
                    self.ground_m += d;
                    Some(geo::bearing_deg(plat, plon, lat, lon))
                } else {
                    None
                }
            }
        }
    }

    /// The latest fix, or `None` before any fix.
    pub fn position(&self) -> Option<(f64, f64)> {
        self.last
    }

    /// The current heading in degrees (bearing from the previous kept fix to
    /// the latest), or `None` while the aircraft has not moved far enough for a
    /// heading to be real.
    pub fn heading_deg(&self) -> Option<f64> {
        let (p, l) = (self.prev?, self.last?);
        Some(geo::bearing_deg(p.0, p.1, l.0, l.1))
    }

    /// Total ground distance in meters over every kept move.
    pub fn ground_distance_m(&self) -> f64 {
        self.ground_m
    }

    /// Range in meters from the latest fix to a target point, or `None` before
    /// any fix.
    pub fn range_to_m(&self, target_lat: f64, target_lon: f64) -> Option<f64> {
        let l = self.last?;
        Some(geo::distance_m(l.0, l.1, target_lat, target_lon))
    }

    /// Bearing in degrees from the latest fix to a target point, or `None`
    /// before any fix.
    pub fn bearing_to(&self, target_lat: f64, target_lon: f64) -> Option<f64> {
        let l = self.last?;
        Some(geo::bearing_deg(l.0, l.1, target_lat, target_lon))
    }

    /// Whether the aircraft is closing on or opening from a target, comparing
    /// the range at the last two kept fixes. `eps_m` is the dead band in
    /// meters below which the change counts as [`RangeTrend::Steady`]. `None`
    /// until two distinct fixes have arrived.
    pub fn trend_to(&self, target_lat: f64, target_lon: f64, eps_m: f64) -> Option<RangeTrend> {
        let (p, l) = (self.prev?, self.last?);
        let rp = geo::distance_m(p.0, p.1, target_lat, target_lon);
        let rl = geo::distance_m(l.0, l.1, target_lat, target_lon);
        let d = rl - rp;
        Some(if d < -eps_m {
            RangeTrend::Closing
        } else if d > eps_m {
            RangeTrend::Opening
        } else {
            RangeTrend::Steady
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geo::{angle_diff_deg, distance_m};

    #[test]
    fn no_heading_until_it_moves() {
        let mut t = Trajectory::new();
        // First fix: nothing to compare to.
        assert_eq!(t.update(45.55, -122.95), None);
        // A jitter of under MIN_MOVE_M (about 1 m north) is ignored.
        assert_eq!(t.update(45.550009, -122.95), None);
        assert_eq!(t.heading_deg(), None);
        assert_eq!(t.ground_distance_m(), 0.0);
    }

    #[test]
    fn heading_due_north_and_east() {
        let mut t = Trajectory::new();
        t.update(45.55, -122.95);
        // About 11 m north.
        let h = t.update(45.5501, -122.95).unwrap();
        assert!(angle_diff_deg(h, 0.0) < 1.0, "north heading {h}");
        // Then about 8 m east.
        let h = t.update(45.5501, -122.94990).unwrap();
        assert!(angle_diff_deg(h, 90.0) < 2.0, "east heading {h}");
    }

    #[test]
    fn closing_and_opening_on_a_target() {
        // Target to the north of the flight path.
        let (tlat, tlon) = (45.60, -122.95);
        let mut t = Trajectory::new();
        t.update(45.55, -122.95);
        // Move north, toward the target.
        t.update(45.56, -122.95);
        assert_eq!(t.trend_to(tlat, tlon, 1.0), Some(RangeTrend::Closing));
        let r1 = t.range_to_m(tlat, tlon).unwrap();
        // Move south, away from the target.
        t.update(45.54, -122.95);
        assert_eq!(t.trend_to(tlat, tlon, 1.0), Some(RangeTrend::Opening));
        let r2 = t.range_to_m(tlat, tlon).unwrap();
        assert!(r2 > r1, "{r2} > {r1}");
        // Bearing to a target due north is about 0 degrees.
        let b = t.bearing_to(tlat, tlon).unwrap();
        assert!(angle_diff_deg(b, 0.0) < 1.0, "bearing {b}");
    }

    #[test]
    fn steady_within_dead_band() {
        // Two fixes equidistant from a target east of both: range barely changes.
        let (tlat, tlon) = (45.55, -122.0);
        let mut t = Trajectory::new();
        t.update(45.5501, -122.95);
        t.update(45.5499, -122.95);
        let rp = distance_m(45.5501, -122.95, tlat, tlon);
        let rl = distance_m(45.5499, -122.95, tlat, tlon);
        // Hand check: the two ranges differ by only a few meters.
        assert!((rp - rl).abs() < 30.0);
        assert_eq!(t.trend_to(tlat, tlon, 50.0), Some(RangeTrend::Steady));
    }
}
