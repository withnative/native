//! Monotone symbolic quantities and distinct-item summation.
//! Σceil(b_i/d) <= ceil(Σb_i/d)+k-1. Each syntactic occurrence pays
//! independently; repeating/projection/copy multiplicities are retained.
use crate::charges::Quantity;
use crate::symbolic_control::{self as control, Resource};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

#[cfg(any(test, feature = "native-proof-tools"))]
pub(crate) fn native_layout() -> (usize, usize) {
    (std::mem::size_of::<Node>(), std::mem::size_of::<Sym>())
}

#[derive(Clone)]
pub(crate) struct Sym(Option<Arc<Node>>);
#[derive(Debug)]
enum Node {
    Const(u64),
    Budget {
        quota: Quota,
        input: usize,
    },
    Parameter {
        scope: Option<usize>,
        maximum: Sym,
        total: Sym,
        many: Option<usize>,
    },
    Add(Sym, Sym),
    Mul(Sym, Sym),
    Min(Sym, Sym),
    Max(Sym, Sym),
    Ceil(Sym, u64),
    Sub(Sym, u64),
}
/// Necessary bounds implied by the ONE total compact JSON cap; jointly
/// 5*Entries+Payload <= B (row/envelope punctuation pays first-entry discounts).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Quota {
    Entries,
    Payload,
}
impl Quota {
    fn limit(self) -> u64 {
        match self {
            Self::Entries => crate::input::TOTAL_INPUT_BYTES / 5,
            Self::Payload => crate::input::TOTAL_INPUT_BYTES,
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Saturated;

impl std::fmt::Debug for Sym {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Sym").field(&self.interval()).finish()
    }
}
/// Release every owned edge, INCLUDING total bounds, with an explicit queue.
/// Ordinary shared-Arc release allocates nothing; the last-owner path cannot
/// recurse through a long constructed summary or a hidden total-only chain.
impl Drop for Sym {
    fn drop(&mut self) {
        fn enqueue(node: Node, pending: &mut Vec<Arc<Node>>) {
            let mut edge = |mut child: Sym| {
                if let Some(arc) = child.0.take() {
                    pending.push(arc)
                }
            };
            match node {
                Node::Parameter { maximum, total, .. } => {
                    edge(maximum);
                    edge(total);
                }
                Node::Add(a, b) | Node::Mul(a, b) | Node::Min(a, b) | Node::Max(a, b) => {
                    edge(a);
                    edge(b);
                }
                Node::Ceil(a, _) | Node::Sub(a, _) => edge(a),
                Node::Const(_) | Node::Budget { .. } => {}
            }
        }
        let Some(arc) = self.0.take() else { return };
        let Ok(node) = Arc::try_unwrap(arc) else {
            return;
        };
        let mut pending = Vec::new();
        enqueue(node, &mut pending);
        while let Some(arc) = pending.pop() {
            if let Ok(node) = Arc::try_unwrap(arc) {
                enqueue(node, &mut pending)
            }
        }
    }
}
impl Sym {
    fn new(node: Node) -> Self {
        if !control::spend(Resource::Nodes, 1) {
            return Self::overflow();
        }
        Self(Some(Arc::new(node)))
    }
    fn overflow() -> Self {
        static OVERFLOW: std::sync::OnceLock<Arc<Node>> = std::sync::OnceLock::new();
        Self(Some(
            OVERFLOW
                .get_or_init(|| Arc::new(Node::Const(u64::MAX)))
                .clone(),
        ))
    }
    fn node(&self) -> &Node {
        self.0.as_ref().expect("live symbolic node").as_ref()
    }

    pub(crate) fn c(n: u64) -> Self {
        Self::new(Node::Const(n))
    }
    pub(crate) fn budget(quota: Quota, input: usize) -> Self {
        Self::new(Node::Budget { quota, input })
    }
    pub(crate) fn parameter(scope: usize, maximum: Sym, total: Sym) -> Self {
        Self::new(Node::Parameter {
            scope: Some(scope),
            maximum,
            total,
            many: None,
        })
    }
    pub(crate) fn input(maximum: u64, many: Option<usize>) -> Self {
        Self::new(Node::Parameter {
            scope: None,
            maximum: Self::c(maximum),
            total: Self::c(maximum),
            many,
        })
    }
    fn id(&self) -> usize {
        Arc::as_ptr(self.0.as_ref().expect("live symbolic node")) as usize
    }
    fn constant_value(&self) -> Option<u64> {
        if let Node::Const(v) = *self.node() {
            Some(v)
        } else {
            None
        }
    }
    pub(crate) fn add(&self, other: &Self) -> Self {
        self.clone().saturating_add(other.clone())
    }
    pub(crate) fn mul(&self, other: &Self) -> Self {
        self.clone().saturating_mul(other.clone())
    }
    pub(crate) fn max(&self, other: &Self) -> Self {
        if self.constant_value() == Some(u64::MAX) || other.constant_value() == Some(u64::MAX) {
            return Self::c(u64::MAX);
        }
        if self.id() == other.id() {
            return self.clone();
        }
        if let (Some(a), Some(b)) = (self.constant_value(), other.constant_value()) {
            return Self::c(a.max(b));
        }
        Self::new(Node::Max(self.clone(), other.clone()))
    }
    pub(crate) fn min_bound(&self, other: &Self) -> Self {
        self.clone().min_quantity(other.clone())
    }
    fn children(&self) -> Vec<Sym> {
        if !control::spend(Resource::Cells, 2) {
            return Vec::new();
        }
        match self.node() {
            Node::Const(_) | Node::Budget { .. } => vec![],
            Node::Parameter { maximum, .. } => vec![maximum.clone()],
            Node::Add(a, b) | Node::Mul(a, b) | Node::Min(a, b) | Node::Max(a, b) => {
                vec![a.clone(), b.clone()]
            }
            Node::Ceil(a, _) | Node::Sub(a, _) => vec![a.clone()],
        }
    }
    /// Iterative postorder; a shared DAG node is processed once, even for repeated
    /// constructed doubling. No deep symbolic traversal uses the worker stack.
    fn fold<T: Clone>(&self, visit: impl FnMut(&Sym, &HashMap<usize, T>) -> T) -> Option<T> {
        self.fold_with_bounds(false, visit)
    }
    fn transform<T: Clone>(&self, visit: impl FnMut(&Sym, &HashMap<usize, T>) -> T) -> Option<T> {
        self.fold_with_bounds(true, visit)
    }
    fn fold_with_bounds<T: Clone>(
        &self,
        transform: bool,
        mut visit: impl FnMut(&Sym, &HashMap<usize, T>) -> T,
    ) -> Option<T> {
        if !control::spend(Resource::Cells, 1) {
            return None;
        }
        let mut stack = vec![(self.clone(), false)];
        let mut values = HashMap::new();
        while let Some((s, ready)) = stack.pop() {
            if !control::spend(Resource::Visits, 1) {
                return None;
            }
            if values.contains_key(&s.id()) {
                continue;
            }
            if !ready {
                if !control::spend(Resource::Cells, 3) {
                    return None;
                }
                stack.push((s.clone(), true));
                let children = if transform {
                    if let Node::Parameter { maximum, total, .. } = s.node() {
                        if !control::spend(Resource::Cells, 2) {
                            return None;
                        }
                        vec![maximum.clone(), total.clone()]
                    } else {
                        s.children()
                    }
                } else {
                    s.children()
                };
                for child in children.into_iter().rev() {
                    if !values.contains_key(&child.id()) {
                        stack.push((child, false));
                    }
                }
            } else {
                if !control::spend(Resource::Cells, 1) {
                    return None;
                }
                let value = visit(&s, &values);
                if control::refusal().is_some() {
                    return None;
                }
                values.insert(s.id(), value);
            }
        }
        values.remove(&self.id())
    }
    fn intervals(&self) -> Result<HashMap<usize, Result<u64, Saturated>>, Saturated> {
        let mut intervals = HashMap::new();
        let finished = self.fold(|s, m| {
            let result = (|| {
                let get = |x: &Sym| m[&x.id()];
                match s.node() {
                    Node::Const(v) => {
                        if *v == u64::MAX {
                            Err(Saturated)
                        } else {
                            Ok(*v)
                        }
                    }
                    Node::Budget { quota, .. } => Ok(quota.limit()),
                    Node::Parameter { maximum, .. } => get(maximum),
                    Node::Add(a, b) => get(a)?
                        .checked_add(get(b)?)
                        .filter(|v| *v != u64::MAX)
                        .ok_or(Saturated),
                    Node::Mul(a, b) => get(a)?
                        .checked_mul(get(b)?)
                        .filter(|v| *v != u64::MAX)
                        .ok_or(Saturated),
                    Node::Min(a, b) => Ok(get(a)?.min(get(b)?)),
                    Node::Max(a, b) => Ok(get(a)?.max(get(b)?)),
                    Node::Ceil(a, d) => Ok(get(a)?.ceil_div(*d)),
                    Node::Sub(a, n) => Ok(get(a)?.saturating_sub(*n)),
                }
            })();
            if !control::spend(Resource::Cells, 1) {
                return Err(Saturated);
            }
            intervals.insert(s.id(), result);
            result
        });
        let _ = finished.ok_or(Saturated)?;
        Ok(intervals)
    }
    fn interval(&self) -> Result<u64, Saturated> {
        self.intervals()?.remove(&self.id()).expect("root interval")
    }
    /// Shared JSON quotas couple DIFFERENT input/argument symbols. An affine
    /// upper envelope assigns each input its multiplicity, then spends each
    /// quota only at its largest coefficient. Repeated same-input occurrences
    /// add coefficients; no pass/projection gets a second free allowance.
    pub(crate) fn value(&self) -> Result<u64, Saturated> {
        let intervals = self.intervals()?;
        intervals[&self.id()]?; // overflow remains a refusal even before tightening
        const SCALE: u128 = 4096;
        #[derive(Clone)]
        struct Envelope {
            fixed: u128,
            coefficients: BTreeMap<(Quota, usize), u128>,
        }
        impl Envelope {
            fn bound(&self) -> Option<u128> {
                if !control::spend(Resource::Cells, 2) {
                    return None;
                }
                let (mut entries, mut payload) = (0u128, 0u128);
                for ((q, _), c) in &self.coefficients {
                    match q {
                        Quota::Entries => entries = entries.max(*c),
                        Quota::Payload => payload = payload.max(*c),
                    }
                }
                let cap = crate::input::TOTAL_INPUT_BYTES as u128;
                let independent = entries
                    .checked_mul(Quota::Entries.limit() as u128)?
                    .checked_add(payload.checked_mul(cap)?)?;
                // With e=sum entries and p=sum raw key/string payload, 5e+p<=B.
                // c_e e+c_p p <= max(c_e,5c_p)*B/5. Round only AFTER multiply;
                // no saturation/refusal sentinel is divided away. The previous
                // independent bound remains useful for integer-only entries.
                let coupled = entries
                    .max(payload.checked_mul(5)?)
                    .checked_mul(cap)?
                    .div_ceil(5);
                self.fixed.checked_add(independent.min(coupled))
            }
            fn scale(mut self, n: u128) -> Option<Self> {
                self.fixed = self.fixed.checked_mul(n)?;
                for c in self.coefficients.values_mut() {
                    *c = c.checked_mul(n)?;
                }
                Some(self)
            }
            fn add(mut self, b: Self) -> Option<Self> {
                self.fixed = self.fixed.checked_add(b.fixed)?;
                if !control::spend(Resource::Cells, b.coefficients.len()) {
                    return None;
                }
                for (k, c) in b.coefficients {
                    let v = self.coefficients.entry(k).or_default();
                    *v = v.checked_add(c)?;
                }
                Some(self)
            }
        }
        let envelope = self
            .fold(|s, m: &HashMap<usize, Option<Envelope>>| {
                let get = |x: &Sym| {
                    let envelope = m[&x.id()].as_ref()?;
                    if !control::spend(Resource::Cells, envelope.coefficients.len()) {
                        return None;
                    }
                    Some(envelope.clone())
                };
                match s.node() {
                    Node::Const(n) => Some(Envelope {
                        fixed: (*n as u128).checked_mul(SCALE)?,
                        coefficients: BTreeMap::new(),
                    }),
                    Node::Budget { quota, input } => Some(Envelope {
                        fixed: 0,
                        coefficients: {
                            if !control::spend(Resource::Cells, 1) {
                                return None;
                            }
                            BTreeMap::from([((*quota, *input), SCALE)])
                        },
                    }),
                    Node::Parameter { maximum, .. } => get(maximum),
                    Node::Add(a, b) => get(a)?.add(get(b)?),
                    Node::Mul(a, b) => {
                        // Either valid affine majorant may be chosen globally.
                        let left = get(a)?.scale(intervals[&b.id()].ok()? as u128)?;
                        let right = get(b)?.scale(intervals[&a.id()].ok()? as u128)?;
                        if left.bound()? <= right.bound()? {
                            Some(left)
                        } else {
                            Some(right)
                        }
                    }
                    Node::Min(a, b) => {
                        let a = get(a)?;
                        let b = get(b)?;
                        if a.bound()? <= b.bound()? {
                            Some(a)
                        } else {
                            Some(b)
                        }
                    }
                    Node::Max(a, b) => {
                        let mut a = get(a)?;
                        let b = get(b)?;
                        a.fixed = a.fixed.max(b.fixed);
                        if !control::spend(Resource::Cells, b.coefficients.len()) {
                            return None;
                        }
                        for (k, c) in b.coefficients {
                            let v = a.coefficients.entry(k).or_default();
                            *v = (*v).max(c);
                        }
                        Some(a)
                    }
                    Node::Ceil(a, d) => {
                        let mut a = get(a)?;
                        let d = *d as u128;
                        // ceil(x/d)<=x/d+(d-1)/d. Coefficients round UP.
                        a.fixed = (a.fixed.checked_add((d - 1).checked_mul(SCALE)?)?).div_ceil(d);
                        for c in a.coefficients.values_mut() {
                            *c = (*c).div_ceil(d);
                        }
                        Some(a)
                    }
                    // Omitting subtraction is a safe affine majorant.
                    Node::Sub(a, _) => get(a),
                }
            })
            .flatten()
            .ok_or(Saturated)?;
        let n = envelope.bound().ok_or(Saturated)?.div_ceil(SCALE);
        u64::try_from(n)
            .ok()
            .filter(|n| *n != u64::MAX)
            .ok_or(Saturated)
    }
    /// Maximum single iteration, replacing this scope's variables with their
    /// individual maxima while keeping any enclosing row scope symbolic.
    pub(crate) fn maximum(&self, scope: usize) -> Self {
        self.transform(|s, m: &HashMap<usize, Sym>| {
            let get = |x: &Sym| m[&x.id()].clone();
            match s.node() {
                Node::Parameter {
                    scope: Some(id),
                    maximum,
                    ..
                } if *id == scope => get(maximum),
                Node::Parameter {
                    scope,
                    maximum,
                    total,
                    many,
                } => Self::new(Node::Parameter {
                    scope: *scope,
                    maximum: get(maximum),
                    total: get(total),
                    many: *many,
                }),
                Node::Add(a, b) => get(a).add(&get(b)),
                Node::Mul(a, b) => get(a).mul(&get(b)),
                Node::Min(a, b) => get(a).min_bound(&get(b)),
                Node::Max(a, b) => get(a).max(&get(b)),
                Node::Ceil(a, d) => get(a).ceil_div(*d),
                Node::Sub(a, n) => get(a).saturating_sub(*n),
                _ => s.clone(),
            }
        })
        .unwrap_or_else(Self::overflow)
    }
    pub(crate) fn rebind(&self, from: usize, to: usize) -> Self {
        self.transform(|s, m: &HashMap<usize, Sym>| {
            let get = |x: &Sym| m[&x.id()].clone();
            match s.node() {
                Node::Parameter {
                    scope: Some(id),
                    maximum,
                    total,
                    many,
                } if *id == from => Self::new(Node::Parameter {
                    scope: Some(to),
                    maximum: get(maximum),
                    total: get(total),
                    many: *many,
                }),
                Node::Parameter {
                    scope,
                    maximum,
                    total,
                    many,
                } => Self::new(Node::Parameter {
                    scope: *scope,
                    maximum: get(maximum),
                    total: get(total),
                    many: *many,
                }),
                Node::Add(a, b) => get(a).add(&get(b)),
                Node::Mul(a, b) => get(a).mul(&get(b)),
                Node::Min(a, b) => get(a).min_bound(&get(b)),
                Node::Max(a, b) => get(a).max(&get(b)),
                Node::Ceil(a, d) => get(a).ceil_div(*d),
                Node::Sub(a, n) => get(a).saturating_sub(*n),
                _ => s.clone(),
            }
        })
        .unwrap_or_else(Self::overflow)
    }
    /// Sound sum over distinct items in this pass (including filtered subsets).
    /// Products depending twice on the same item use max(x)*Σy or vice versa,
    /// whichever is tighter. They never receive an unjustified free total-B pass.
    pub(crate) fn sum(&self, scope: usize, count: &Sym) -> Self {
        #[derive(Clone)]
        struct Summed {
            dependent: bool,
            total: Sym,
            maximum: Sym,
        }
        self.fold(|s, m: &HashMap<usize, Summed>| {
            let get = |x: &Sym| m[&x.id()].clone();
            let dependent = match s.node() {
                Node::Parameter {
                    scope: Some(id), ..
                } if *id == scope => true,
                _ => s.children().iter().any(|c| m[&c.id()].dependent),
            };
            if !dependent {
                return Summed {
                    dependent: false,
                    total: s.mul(count),
                    maximum: s.clone(),
                };
            }
            let (total, maximum) = match s.node() {
                Node::Parameter {
                    scope: Some(id),
                    maximum,
                    total,
                    ..
                } if *id == scope => (total.clone(), maximum.clone()),
                Node::Parameter { maximum, .. } => {
                    let a = get(maximum);
                    (a.total, a.maximum)
                }
                Node::Add(a, b) => {
                    let a = get(a);
                    let b = get(b);
                    (a.total.add(&b.total), a.maximum.add(&b.maximum))
                }
                Node::Mul(a, b) => {
                    let a = get(a);
                    let b = get(b);
                    (
                        a.maximum.mul(&b.total).min_bound(&b.maximum.mul(&a.total)),
                        a.maximum.mul(&b.maximum),
                    )
                }
                Node::Min(a, b) => {
                    let a = get(a);
                    let b = get(b);
                    (a.total.min_bound(&b.total), a.maximum.min_bound(&b.maximum))
                }
                Node::Max(a, b) => {
                    let a = get(a);
                    let b = get(b);
                    (a.total.add(&b.total), a.maximum.max(&b.maximum))
                }
                Node::Ceil(a, d) => {
                    let a = get(a);
                    (
                        a.total.ceil_div(*d).add(&count.clone().saturating_sub(1)),
                        a.maximum.ceil_div(*d),
                    )
                }
                Node::Sub(a, n) => {
                    let a = get(a);
                    (a.total, a.maximum.saturating_sub(*n))
                }
                Node::Const(_) | Node::Budget { .. } => unreachable!("constant is independent"),
            };
            Summed {
                dependent,
                total,
                maximum,
            }
        })
        .map(|s| s.total)
        .unwrap_or_else(Self::overflow)
    }
    /// Resource multiplication, including implicit scans/copies and same-input
    /// self-products. Root many factors survive map/filter/concat provenance.
    pub(crate) fn cross_product(&self) -> bool {
        self.fold(|s, m: &HashMap<usize, (BTreeSet<usize>, bool)>| {
            let mut factors = BTreeSet::new();
            let mut product = false;
            for child in s.children() {
                let (f, p) = &m[&child.id()];
                if !control::spend(Resource::Cells, f.len()) {
                    return (BTreeSet::new(), true);
                }
                factors.extend(f);
                product |= p;
            }
            if let Node::Parameter { many: Some(id), .. } = s.node() {
                if !control::spend(Resource::Cells, 1) {
                    return (BTreeSet::new(), true);
                }
                factors.insert(*id);
            }
            if let Node::Mul(a, b) = s.node() {
                product |= !m[&a.id()].0.is_empty() && !m[&b.id()].0.is_empty();
            }
            (factors, product)
        })
        .map(|s| s.1)
        .unwrap_or(true)
    }
}
impl Quantity for Sym {
    fn constant(n: u64) -> Self {
        Self::c(n)
    }
    fn saturating_add(self, other: Self) -> Self {
        if self.constant_value() == Some(u64::MAX) || other.constant_value() == Some(u64::MAX) {
            return Self::c(u64::MAX);
        }
        if self.constant_value() == Some(0) {
            return other;
        }
        if other.constant_value() == Some(0) {
            return self;
        }
        if let (Some(a), Some(b)) = (self.constant_value(), other.constant_value()) {
            return Self::c(a.saturating_add(b));
        }
        Self::new(Node::Add(self, other))
    }
    fn saturating_mul(self, other: Self) -> Self {
        if self.constant_value() == Some(u64::MAX) || other.constant_value() == Some(u64::MAX) {
            return Self::c(u64::MAX);
        }
        if self.constant_value() == Some(0) || other.constant_value() == Some(0) {
            // A pending overflow is as sticky as the literal sentinel. Finite
            // zero products still disappear, including their many provenance.
            return if self.interval().is_err() || other.interval().is_err() {
                Self::c(u64::MAX)
            } else {
                Self::c(0)
            };
        }
        if self.constant_value() == Some(1) {
            return other;
        }
        if other.constant_value() == Some(1) {
            return self;
        }
        if let (Some(a), Some(b)) = (self.constant_value(), other.constant_value()) {
            return Self::c(a.saturating_mul(b));
        }
        Self::new(Node::Mul(self, other))
    }
    fn saturating_sub(self, n: u64) -> Self {
        if self.constant_value() == Some(u64::MAX) {
            return self;
        }
        if let Some(v) = self.constant_value() {
            return Self::c(v.saturating_sub(n));
        }
        if n == 0 {
            self
        } else {
            Self::new(Node::Sub(self, n))
        }
    }
    fn min_quantity(self, other: Self) -> Self {
        if self.constant_value() == Some(u64::MAX) || other.constant_value() == Some(u64::MAX) {
            return Self::c(u64::MAX);
        }
        if self.id() == other.id() {
            return self;
        }
        if let (Some(a), Some(b)) = (self.constant_value(), other.constant_value()) {
            return Self::c(a.min(b));
        }
        Self::new(Node::Min(self, other))
    }
    fn ceil_div(self, d: u64) -> Self {
        if self.constant_value() == Some(u64::MAX) {
            return self;
        }
        assert!(d > 0);
        if let Some(v) = self.constant_value() {
            return Self::c(v.ceil_div(d));
        }
        Self::new(Node::Ceil(self, d))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn auxiliary_control_stops_construction_and_partial_symbolic_walks() {
        use crate::symbolic_control::{account_limits, Counts};
        let (_, counts, refused) = account_limits(
            Counts {
                nodes: 3,
                visits: 100,
                cells: 100,
                shapes: 100,
            },
            || {
                let p = Sym::input(10, None);
                let exhausted = p.add(&Sym::c(1));
                assert!(exhausted.value().is_err());
                assert_eq!(exhausted.mul(&Sym::c(0)).constant_value(), Some(u64::MAX));
            },
        );
        assert_eq!(counts.nodes, 3);
        assert_eq!(refused.unwrap().cap, "symbolic_nodes");
        let mut p = Sym::input(1, None);
        for _ in 0..100 {
            p = p.add(&Sym::c(1));
        }
        let (_, counts, refused) = account_limits(
            Counts {
                nodes: 1000,
                visits: 5,
                cells: 1000,
                shapes: 1000,
            },
            || {
                assert!(p.value().is_err());
                assert!(p.rebind(1, 2).value().is_err());
                assert!(p.cross_product()); // cannot be used as a successful bound
            },
        );
        assert_eq!(counts.visits, 5);
        assert_eq!(refused.unwrap().cap, "symbolic_visits");
        assert_eq!(p.value().unwrap(), 101); // account restored, graph unmodified
    }
    #[test]
    fn symbolic_long_and_hidden_total_graphs_drop_without_recursive_stack() {
        for stack in [4 * 1024 * 1024, 8 * 1024 * 1024] {
            std::thread::Builder::new()
                .stack_size(stack)
                .spawn(|| {
                    let mut sum = Sym::input(1, None);
                    for _ in 0..20_000 {
                        sum = sum.add(&Sym::c(1));
                    }
                    assert_eq!(sum.value().unwrap(), 20_001);
                    assert!(format!("{sum:?}").len() < 80);
                    let shared = sum.clone();
                    drop(sum);
                    assert_eq!(shared.value().unwrap(), 20_001);
                    drop(shared);
                    let mut total = Sym::c(1);
                    for scope in 0..20_000 {
                        total = Sym::parameter(scope, Sym::c(1), total);
                    }
                    assert_eq!(total.value().unwrap(), 1);
                    drop(total);
                    let child = Sym::input(2, None);
                    drop(Sym(Some(Arc::new(Node::Add(child.clone(), child)))));
                })
                .unwrap()
                .join()
                .unwrap();
        }
    }
    #[test]
    fn distinct_pass_sums_price_rounding_and_duplication() {
        let count = Sym::input(5000, Some(0));
        let entries = Sym::budget(Quota::Entries, 0);
        let payload = Sym::budget(Quota::Payload, 0);
        let row_entries = Sym::parameter(1, entries.clone(), entries.clone());
        let row_payload = Sym::parameter(1, payload.clone(), payload.clone());
        let bytes = row_entries.mul(&Sym::c(72)).add(&row_payload);
        let nodes = Sym::c(1).add(&row_entries);
        let row = crate::charges::comprehension_item_bind(nodes.clone(), bytes.clone());
        let total = row.work.sum(1, &count).value().unwrap();
        assert!(total < 500_000, "{total}");
        // A second syntactic copy doubles its aggregate allowance, not a free pass.
        assert!(
            bytes.add(&bytes).sum(1, &count).value().unwrap()
                >= 2 * bytes.sum(1, &count).value().unwrap()
        );
        let rounded = Sym::parameter(2, Sym::c(1), Sym::c(65))
            .ceil_div(64)
            .sum(2, &Sym::c(65))
            .value()
            .unwrap();
        assert!(rounded >= 65);
        // One maximal row is still required for temporary peaks.
        assert_eq!(
            bytes.maximum(1).value().unwrap(),
            (72 * crate::input::TOTAL_INPUT_BYTES).div_ceil(5)
        );
    }
    #[test]
    fn one_total_json_quota_couples_inputs_but_repeated_occurrences_pay() {
        let a = Sym::budget(Quota::Payload, 0);
        let b = Sym::budget(Quota::Payload, 1);
        let cap = crate::input::TOTAL_INPUT_BYTES;
        assert_eq!(a.add(&b).value().unwrap(), cap);
        assert_eq!(a.add(&a).add(&b).value().unwrap(), 2 * cap);
        let entries = Sym::budget(Quota::Entries, 2);
        let mixed = entries.mul(&Sym::c(72)).add(&a).add(&b);
        assert_eq!(mixed.value().unwrap(), (72 * cap).div_ceil(5));
        assert_eq!(mixed.add(&mixed).value().unwrap(), (144 * cap).div_ceil(5));
        // Different inputs may spend different portions; repeated projections
        // accumulate coefficients before the same joint budget is applied.
        for e in [0, 1, cap / 10, cap / 5] {
            let p = cap - 5 * e;
            assert!(72 * e + p <= mixed.value().unwrap());
            assert!(144 * e + 2 * p <= mixed.add(&mixed).value().unwrap());
        }
        for pending in [
            Sym::c(u64::MAX),
            Sym::input(u64::MAX - 1, None).add(&Sym::c(1)),
            Sym::input(u64::MAX, None).add(&Sym::c(1)),
        ] {
            assert!(pending.value().is_err());
            assert!(pending.mul(&Sym::c(0)).value().is_err());
            assert!(Sym::c(0).mul(&pending).value().is_err());
        }
        let finite = Sym::input(5000, Some(0)).mul(&Sym::input(5000, Some(1)));
        assert_eq!(finite.mul(&Sym::c(0)).value().unwrap(), 0);
        assert!(!finite.mul(&Sym::c(0)).cross_product());
        assert!(!Sym::c(0).mul(&finite).cross_product());
        assert!(Sym::c(u64::MAX).ceil_div(64).value().is_err());
        assert!(Sym::c(u64::MAX - 1)
            .add(&Sym::c(2))
            .ceil_div(64)
            .value()
            .is_err());
    }
    #[test]
    fn nested_parameter_transforms_rebuild_both_bounds_without_total_provenance() {
        let p = Sym::parameter(1, Sym::c(10), Sym::c(10));
        let q = Sym::parameter(2, p.clone(), p.clone());
        assert_eq!(q.maximum(1).sum(1, &Sym::c(2)).value().unwrap(), 20);
        assert_eq!(q.sum(2, &Sym::c(1)).sum(1, &Sym::c(2)).value().unwrap(), 10);
        assert_eq!(
            q.rebind(1, 3)
                .maximum(3)
                .sum(3, &Sym::c(2))
                .value()
                .unwrap(),
            20
        );
        assert_eq!(
            q.rebind(1, 3)
                .sum(2, &Sym::c(1))
                .sum(3, &Sym::c(2))
                .value()
                .unwrap(),
            10
        );
        let only_total = Sym::parameter(2, Sym::c(10), p);
        assert_eq!(
            only_total
                .rebind(1, 3)
                .sum(2, &Sym::c(1))
                .sum(1, &Sym::c(2))
                .value()
                .unwrap(),
            20
        );
        assert_eq!(
            only_total
                .rebind(1, 3)
                .sum(2, &Sym::c(1))
                .sum(3, &Sym::c(2))
                .value()
                .unwrap(),
            10
        );
        let n = Sym::input(5000, Some(0));
        let row = Sym::parameter(1, Sym::c(10), n);
        // Aggregate total is summation evidence, not the per-item cost factor.
        assert!(!row.mul(&Sym::input(5000, Some(1))).cross_product());
    }
    #[test]
    fn product_detection_tracks_actual_resource_factors() {
        let n = Sym::input(5000, Some(0));
        let m = Sym::input(5000, Some(1));
        assert!(n.mul(&n).cross_product());
        assert!(n.mul(&m).cross_product());
        assert!(!n.mul(&Sym::c(8)).cross_product());
    }
}
