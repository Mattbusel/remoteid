//! Small geodesy helpers that work without `std` and without dependencies.
//!
//! With the `std` feature the platform math functions are used. Without it
//! the functions below fall back to short polynomial approximations that are
//! accurate to better than 1e-9 relative (sine, cosine, square root) and
//! 1e-6 rad (arc tangent), far below what the plausibility checks need.

/// `f64::abs` for `no_std` on the minimum supported Rust version (the
/// inherent method only reached `core` in Rust 1.85).
pub(crate) trait FloatExt {
    fn fabs(self) -> f64;
}

impl FloatExt for f64 {
    fn fabs(self) -> f64 {
        f64::from_bits(self.to_bits() & !(1u64 << 63))
    }
}

/// Mean Earth radius in meters (IUGG).
pub const EARTH_RADIUS_M: f64 = 6_371_008.8;

const PI: f64 = core::f64::consts::PI;

#[cfg(feature = "std")]
pub(crate) fn sqrt(x: f64) -> f64 {
    x.sqrt()
}
#[cfg(feature = "std")]
pub(crate) fn sin(x: f64) -> f64 {
    x.sin()
}
#[cfg(feature = "std")]
pub(crate) fn cos(x: f64) -> f64 {
    x.cos()
}
#[cfg(feature = "std")]
pub(crate) fn atan2(y: f64, x: f64) -> f64 {
    y.atan2(x)
}

#[cfg(not(feature = "std"))]
pub(crate) use fallback::{atan2, cos, sin, sqrt};

/// Portable implementations, also compiled with `std` so tests can compare
/// them against the platform functions.
#[allow(dead_code)]
pub(crate) mod fallback {
    use super::PI;

    /// Square root by Newton iteration from an exponent-halving guess.
    pub(crate) fn sqrt(x: f64) -> f64 {
        if x.is_nan() || x < 0.0 {
            return f64::NAN;
        }
        if x == 0.0 || x.is_infinite() {
            return x;
        }
        // Halve the exponent for the first guess.
        let bits = x.to_bits();
        let mut y = f64::from_bits((bits >> 1) + (1023u64 << 51));
        for _ in 0..6 {
            y = 0.5 * (y + x / y);
        }
        y
    }

    /// Reduces `x` to [-pi, pi].
    fn reduce(x: f64) -> f64 {
        let two_pi = 2.0 * PI;
        let k = (x / two_pi + if x >= 0.0 { 0.5 } else { -0.5 }) as i64;
        x - k as f64 * two_pi
    }

    /// Sine by Taylor series on [-pi/2, pi/2] after reduction.
    pub(crate) fn sin(x: f64) -> f64 {
        if !x.is_finite() {
            return f64::NAN;
        }
        let mut r = reduce(x);
        if r > PI / 2.0 {
            r = PI - r;
        } else if r < -PI / 2.0 {
            r = -PI - r;
        }
        let r2 = r * r;
        // Terms up to r^19: error below 1e-16 on [-pi/2, pi/2].
        let mut term = r;
        let mut sum = r;
        let mut n = 1.0;
        for _ in 0..9 {
            term *= -r2 / ((n + 1.0) * (n + 2.0));
            sum += term;
            n += 2.0;
        }
        sum
    }

    /// Cosine as a shifted sine.
    pub(crate) fn cos(x: f64) -> f64 {
        sin(x + PI / 2.0)
    }

    /// Arc tangent of `t` for |t| <= 1 (series after two argument halvings).
    fn atan_unit(t: f64) -> f64 {
        // atan(t) = 2 atan(t / (1 + sqrt(1 + t^2))), applied twice brings
        // |t| below tan(pi/16) ~ 0.199 where the series converges fast.
        let t1 = t / (1.0 + sqrt(1.0 + t * t));
        let t2 = t1 / (1.0 + sqrt(1.0 + t1 * t1));
        let t2sq = t2 * t2;
        let mut term = t2;
        let mut sum = t2;
        let mut k = 1.0;
        for _ in 0..12 {
            term *= -t2sq;
            k += 2.0;
            sum += term / k;
        }
        4.0 * sum
    }

    /// Two-argument arc tangent with the usual quadrant rules.
    pub(crate) fn atan2(y: f64, x: f64) -> f64 {
        if x.is_nan() || y.is_nan() {
            return f64::NAN;
        }
        if x == 0.0 && y == 0.0 {
            return 0.0;
        }
        let ax = if x < 0.0 { -x } else { x };
        let ay = if y < 0.0 { -y } else { y };
        let a = if ax >= ay {
            atan_unit(ay / ax)
        } else {
            PI / 2.0 - atan_unit(ax / ay)
        };
        let a = if x < 0.0 { PI - a } else { a };
        if y < 0.0 {
            -a
        } else {
            a
        }
    }
}

/// Great circle distance in meters between two WGS84 points (haversine on a
/// sphere; good to about 0.5% which is plenty for plausibility checks).
pub fn distance_m(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let (p1, p2) = (lat1.to_radians(), lat2.to_radians());
    let dp = p2 - p1;
    let dl = (lon2 - lon1).to_radians();
    let s1 = sin(dp / 2.0);
    let s2 = sin(dl / 2.0);
    let a = s1 * s1 + cos(p1) * cos(p2) * s2 * s2;
    let a = a.clamp(0.0, 1.0);
    2.0 * EARTH_RADIUS_M * atan2(sqrt(a), sqrt(1.0 - a))
}

/// Initial bearing from point 1 to point 2 in degrees, 0 = north, clockwise,
/// in [0, 360).
pub fn bearing_deg(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let (p1, p2) = (lat1.to_radians(), lat2.to_radians());
    let dl = (lon2 - lon1).to_radians();
    let y = sin(dl) * cos(p2);
    let x = cos(p1) * sin(p2) - sin(p1) * cos(p2) * cos(dl);
    let b = atan2(y, x).to_degrees();
    if b >= 360.0 {
        0.0
    } else if b < 0.0 {
        b + 360.0
    } else {
        b
    }
}

/// Smallest absolute difference between two angles in degrees, in [0, 180].
pub fn angle_diff_deg(a: f64, b: f64) -> f64 {
    if !a.is_finite() || !b.is_finite() {
        return f64::NAN;
    }
    // No float `%`: it lowers to `fmod`, which bare metal targets lack.
    let mut d = a - b;
    d -= 360.0 * ((d / 360.0) as i64) as f64;
    if d < 0.0 {
        d += 360.0;
    }
    if d > 180.0 {
        360.0 - d
    } else {
        d
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn fallback_matches_std() {
        let mut x = -20.0f64;
        while x < 20.0 {
            assert!((fallback::sin(x) - x.sin()).abs() < 1e-12, "sin {x}");
            assert!((fallback::cos(x) - x.cos()).abs() < 1e-12, "cos {x}");
            x += 0.0137;
        }
        for v in [0.0, 1e-300, 1e-9, 0.5, 2.0, 1e6, 6.3e12, f64::MAX] {
            let s = fallback::sqrt(v);
            assert!((s - v.sqrt()).abs() <= v.sqrt() * 1e-15, "sqrt {v}");
        }
        let mut a = 0.0f64;
        while a < 2.0 * PI {
            let (y, x) = (a.sin() * 3.0, a.cos() * 3.0);
            assert!(
                (fallback::atan2(y, x) - y.atan2(x)).abs() < 1e-9,
                "atan2 {a}"
            );
            a += 0.01;
        }
        assert_eq!(fallback::atan2(0.0, -1.0), PI);
    }

    #[test]
    fn known_distance_and_bearing() {
        // One degree of latitude is about 111.2 km on the mean sphere.
        let d = distance_m(47.0, 8.0, 48.0, 8.0);
        assert!((d - 111_195.0).abs() < 50.0, "{d}");
        assert!((bearing_deg(47.0, 8.0, 48.0, 8.0) - 0.0).abs() < 1e-9);
        let b = bearing_deg(0.0, 0.0, 0.0, 1.0);
        assert!((b - 90.0).abs() < 1e-9, "{b}");
        assert_eq!(angle_diff_deg(350.0, 10.0), 20.0);
        assert_eq!(angle_diff_deg(-170.0, 170.0), 20.0);
    }
}
