use once_cell::sync::Lazy;
use parking_lot::RwLock;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const STABILITY_HYSTERESIS_MS: u64 = 60;
pub const UNPROBED_DEFAULT_SCORE_MS: u64 = 250;
pub const USEFUL_SUCCESS_BONUS_MS: u64 = 15;
pub const MAX_USEFUL_SUCCESS_BONUS_MS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DcTargetKey {
    pub dc_id: i32,
    pub is_media: bool,
}

impl DcTargetKey {
    pub fn new(dc_id: i32, is_media: bool) -> Self {
        Self { dc_id, is_media }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainStats {
    pub domain: String,
    pub probe_rtt_ms: Option<u64>,
    pub useful_success_count: u64,
    pub failure_count: u64,
    pub consecutive_failures: u32,
    pub last_useful_at_ms: u64,
    pub last_failure_at_ms: u64,
}

impl DomainStats {
    pub fn new(domain: String) -> Self {
        Self {
            domain,
            probe_rtt_ms: None,
            useful_success_count: 0,
            failure_count: 0,
            consecutive_failures: 0,
            last_useful_at_ms: 0,
            last_failure_at_ms: 0,
        }
    }

    /// Composite score calculation:
    /// Lower score = better candidate.
    /// Incorporates:
    /// 1. Base probe RTT (or default unprobed baseline).
    /// 2. Useful success bonus: each verified useful RX reduces score by 15ms (up to 60ms).
    /// 3. Failure penalty: consecutive failures rapidly penalize broken domains (+100ms, +250ms, +1000ms),
    ///    plus cumulative failures penalty.
    pub fn calculate_score(&self) -> u64 {
        let base = self.probe_rtt_ms.unwrap_or(UNPROBED_DEFAULT_SCORE_MS);
        let useful_bonus = std::cmp::min(
            self.useful_success_count.saturating_mul(USEFUL_SUCCESS_BONUS_MS),
            MAX_USEFUL_SUCCESS_BONUS_MS,
        );
        let fail_penalty = match self.consecutive_failures {
            0 => 0,
            1 => 100,
            2 => 250,
            _ => 1000,
        } + self.failure_count.saturating_mul(20);

        base.saturating_sub(useful_bonus).saturating_add(fail_penalty)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankedDomainSummary {
    pub domain: String,
    pub probe_rtt_ms: Option<u64>,
    pub useful_success_count: u64,
    pub failure_count: u64,
    pub consecutive_failures: u32,
    pub score: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetRouteStatus {
    pub dc_id: i32,
    pub is_media: bool,
    pub active_domain: Option<String>,
    pub rankings: Vec<RankedDomainSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainBalancerStatus {
    pub current_network_generation: u64,
    pub routes: Vec<TargetRouteStatus>,
}

/// Aggregated health snapshot across all active routes in the current network generation.
#[derive(Debug, Clone)]
pub struct BalancerHealthSummary {
    pub active_domain: Option<String>,
    pub healthy_domain_count: usize,
    pub total_domain_count: usize,
    pub min_probe_rtt_ms: Option<u64>,
    pub median_probe_rtt_ms: Option<u64>,
    pub total_useful_success_count: u64,
    pub total_failure_count: u64,
}

pub fn normalize_domain(domain: &str) -> String {
    let s = domain.trim();
    if let Some(pos) = s.find("://") {
        return normalize_domain(&s[pos + 3..]);
    }
    let host = s.split('/').next().unwrap_or(s);
    let host = host.split(':').next().unwrap_or(host);
    if host.parse::<std::net::IpAddr>().is_ok() {
        return String::new();
    }
    if let Some(rest) = host.strip_prefix("kws") {
        if let Some(dot_idx) = rest.find('.') {
            let prefix = &rest[..dot_idx];
            if !prefix.is_empty() && prefix.chars().all(|c| c.is_ascii_digit() || c == '-') {
                let rest_domain = &rest[dot_idx + 1..];
                if rest_domain.parse::<std::net::IpAddr>().is_ok() {
                    return String::new();
                }
                return rest_domain.to_ascii_lowercase();
            }
        }
    }
    host.to_ascii_lowercase()
}

#[derive(Debug, Clone, Default)]
pub struct IsolatedDomainCandidates {
    /// Strictly disjoint candidates owned by this `(dc_id, is_media)` slot:
    /// explicit pin, healthy non-colliding active domain, or healthy unoccupied shard (`idx % 10 == slot_idx`).
    pub exclusive_primary: Vec<String>,
    /// Unoccupied candidates outside this slot's own shard (used only when all `exclusive_primary`
    /// candidates are failing or in 429 cooldown, or when the pool has fewer than 10 domains).
    pub unoccupied_overflow: Vec<String>,
    /// Occupied fallback candidates already claimed by other DC slots (used ONLY when ZERO
    /// unoccupied non-429 candidates exist anywhere).
    pub shared_fallback: Vec<String>,
}

pub struct Balancer {
    domains: Vec<String>,
    current_generation: u64,
    // (network_generation, DcTargetKey) -> domain -> DomainStats
    stats: HashMap<(u64, DcTargetKey), HashMap<String, DomainStats>>,
    // (network_generation, DcTargetKey) -> active_domain
    active_domains: HashMap<(u64, DcTargetKey), String>,
    // (network_generation, DcTargetKey) -> currently claimed/in-flight domains (prevents concurrent DC collisions)
    in_flight_claims: HashMap<(u64, DcTargetKey), std::collections::HashSet<String>>,
}

pub static BALANCER: Lazy<RwLock<Balancer>> = Lazy::new(|| RwLock::new(Balancer::new()));

impl Default for Balancer {
    fn default() -> Self {
        Self::new()
    }
}

impl Balancer {
    pub fn new() -> Self {
        Self {
            domains: Vec::new(),
            current_generation: 1,
            stats: HashMap::new(),
            active_domains: HashMap::new(),
            in_flight_claims: HashMap::new(),
        }
    }

    pub fn current_generation(&self) -> u64 {
        self.current_generation
    }

    pub fn set_network_generation(&mut self, gen: u64) {
        self.notify_generation_change(gen);
    }

    /// When network generation changes (e.g. Wi-Fi <-> Cellular handover or operator switch),
    /// the domain balancer transitions to the new generation.
    /// Stale winners from previous operators/networks are NOT inherited.
    pub fn notify_generation_change(&mut self, new_generation: u64) {
        if new_generation == 0 || new_generation == self.current_generation {
            return;
        }
        self.current_generation = new_generation;
        // Prune older generations to avoid memory leakage and ensure isolation
        self.stats.retain(|(gen, _), _| *gen == new_generation);
        self.active_domains
            .retain(|(gen, _), _| *gen == new_generation);
        self.in_flight_claims
            .retain(|(gen, _), _| *gen == new_generation);
    }

    pub fn update_domains_list(&mut self, domains_list: &[String]) {
        let mut normalized: Vec<String> = domains_list
            .iter()
            .map(|d| normalize_domain(d))
            .filter(|d| !d.is_empty())
            .collect();
        normalized.sort();
        normalized.dedup();

        let mut current_sorted = self.domains.clone();
        current_sorted.sort();

        if current_sorted == normalized {
            return;
        }

        self.domains = normalized;
    }

    /// Update probe ranking specifically for `(dc_id, is_media)` on the current generation.
    pub fn update_ranked_domains_for_dc(
        &mut self,
        dc_id: i32,
        is_media: bool,
        ranked: Vec<(String, u64)>,
    ) {
        if ranked.is_empty() {
            return;
        }
        let gen = self.current_generation;
        let target_key = DcTargetKey::new(dc_id, is_media);

        for (domain_raw, latency_ms) in ranked {
            let domain = normalize_domain(&domain_raw);
            if domain.is_empty() {
                continue;
            }
            let map = self.stats.entry((gen, target_key)).or_default();
            let entry = map
                .entry(domain.clone())
                .or_insert_with(|| DomainStats::new(domain));

            match entry.probe_rtt_ms {
                Some(old_lat) => {
                    entry.probe_rtt_ms = Some((old_lat * 7 + latency_ms * 3) / 10);
                }
                None => {
                    entry.probe_rtt_ms = Some(latency_ms);
                }
            }
        }

        self.recompute_active_domain_for_target(gen, target_key);
    }

    pub fn update_domain_for_dc(&mut self, dc_id: i32, is_media: bool, domain: &str) -> bool {
        let domain_norm = normalize_domain(domain);
        if domain_norm.is_empty() {
            return false;
        }
        let gen = self.current_generation;
        let target_key = DcTargetKey::new(dc_id, is_media);

        let per_dc = crate::config::is_flowseal_per_dc_enabled();
        if per_dc {
            let own_pin = crate::config::get_flowseal_pinned_domain(dc_id, is_media);
            let is_own_pin = own_pin.as_deref() == Some(domain_norm.as_str());
            if !is_own_pin {
                let other_active = self.other_active_domains(dc_id, is_media);
                if other_active.contains(&domain_norm) {
                    // Do not let a shared fallback connection overwrite a slot's active domain
                    // with a CDN already owned by another DC.
                    if let Some(cur) = self.active_domains.get(&(gen, target_key)) {
                        if !cur.is_empty() && !other_active.contains(cur) {
                            return false;
                        }
                    }
                    // Ensure stats entry exists without claiming ownership away from the other DC.
                    let map = self.stats.entry((gen, target_key)).or_default();
                    map.entry(domain_norm.clone())
                        .or_insert_with(|| DomainStats::new(domain_norm));
                    return false;
                }
            }
        }

        let current = self.active_domains.get(&(gen, target_key));
        if current.map(|s| s.as_str()) == Some(&domain_norm) {
            if per_dc {
                // Narrow in-flight claims to the winning domain so runner-ups are released.
                let mut single = std::collections::HashSet::with_capacity(1);
                single.insert(domain_norm);
                self.in_flight_claims.insert((gen, target_key), single);
            }
            return false;
        }
        self.active_domains
            .insert((gen, target_key), domain_norm.clone());
        if per_dc {
            let mut single = std::collections::HashSet::with_capacity(1);
            single.insert(domain_norm.clone());
            self.in_flight_claims.insert((gen, target_key), single);
        }

        // Ensure stats entry exists
        let map = self.stats.entry((gen, target_key)).or_default();
        map.entry(domain_norm.clone())
            .or_insert_with(|| DomainStats::new(domain_norm));

        true
    }

    pub fn get_active_domain_for_dc(&self, dc_id: i32, is_media: bool) -> Option<String> {
        let gen = self.current_generation;
        let target_key = DcTargetKey::new(dc_id, is_media);
        self.active_domains
            .get(&(gen, target_key))
            .filter(|s| !s.is_empty())
            .cloned()
    }

    /// Returns the fastest domain specifically for this `(dc_id, is_media)` on the current generation.
    /// MOB-026: Does NOT fall back to DC2! Each DC and media class is strictly isolated.
    pub fn get_fastest_domain_for_dc(&self, dc_id: i32, is_media: bool) -> Option<String> {
        let gen = self.current_generation;
        let target_key = DcTargetKey::new(dc_id, is_media);

        if let Some(active) = self.active_domains.get(&(gen, target_key)) {
            if !active.is_empty() {
                return Some(active.clone());
            }
        }

        if let Some(stats_map) = self.stats.get(&(gen, target_key)) {
            let mut scored: Vec<(&String, u64)> = stats_map
                .iter()
                .map(|(d, s)| (d, s.calculate_score()))
                .collect();
            scored.sort_by_key(|(_, score)| *score);
            if let Some((best, _)) = scored.first() {
                return Some((*best).clone());
            }
        }

        None
    }

    /// Returns domains ordered by composite score for this specific `(dc_id, is_media)` on the current generation.
    /// MOB-026: Does NOT fall back to DC2!
    pub fn get_domains_for_dc(&self, dc_id: i32, is_media: bool) -> Vec<String> {
        let mut result = Vec::new();
        let mut seen = std::collections::HashSet::new();

        let gen = self.current_generation;
        let target_key = DcTargetKey::new(dc_id, is_media);

        // 1. Current active domain for this specific (network_generation, target_key)
        if let Some(active) = self.active_domains.get(&(gen, target_key)) {
            if !active.is_empty() {
                result.push(active.clone());
                seen.insert(active.clone());
            }
        }

        // 2. Ranked domains specifically for this (gen, target_key) sorted by effective score
        if let Some(stats_map) = self.stats.get(&(gen, target_key)) {
            let mut scored: Vec<(&String, u64)> = stats_map
                .iter()
                .map(|(d, s)| (d, s.calculate_score()))
                .collect();
            scored.sort_by_key(|(_, score)| *score);
            for (d, _) in scored {
                if !seen.contains(d) {
                    result.push(d.clone());
                    seen.insert(d.clone());
                }
            }
        }

        // 3. Fallback to remaining unranked configured domains (shuffled for load spread)
        let mut remaining: Vec<String> = self
            .domains
            .iter()
            .map(|d| normalize_domain(d))
            .filter(|d| !seen.contains(d) && !d.is_empty())
            .collect();
        let mut rng = rand::thread_rng();
        remaining.shuffle(&mut rng);

        for d in remaining {
            if !seen.contains(&d) {
                result.push(d.clone());
                seen.insert(d);
            }
        }

        result
    }

    fn dc_slot_rotation_index(dc_id: i32, is_media: bool) -> usize {
        let dc_idx = (dc_id.clamp(1, 5) - 1) as usize;
        dc_idx * 2 + if is_media { 1 } else { 0 }
    }

    const ISOLATED_SLOT_COUNT: usize = 10;

    /// Collects active domains currently owned by other `(dc_id, is_media)` slots
    /// in the active network generation.
    pub fn other_active_domains(
        &self,
        dc_id: i32,
        is_media: bool,
    ) -> std::collections::HashSet<String> {
        let gen = self.current_generation;
        let self_key = DcTargetKey::new(dc_id, is_media);
        self.active_domains
            .iter()
            .filter_map(|((g, key), dom)| {
                if *g == gen && *key != self_key && !dom.is_empty() {
                    Some(dom.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Collects both active domains AND currently in-flight claimed domains of other slots.
    pub fn other_occupied_domains(
        &self,
        dc_id: i32,
        is_media: bool,
    ) -> std::collections::HashSet<String> {
        let gen = self.current_generation;
        let self_key = DcTargetKey::new(dc_id, is_media);
        let mut occupied = self.other_active_domains(dc_id, is_media);
        for ((g, key), set) in &self.in_flight_claims {
            if *g == gen && *key != self_key {
                for dom in set {
                    if !dom.is_empty() {
                        occupied.insert(dom.clone());
                    }
                }
            }
        }
        occupied
    }

    /// Atomically replaces the in-flight domain claims for `(dc_id, is_media)` in the active generation.
    pub fn claim_in_flight_domains(&mut self, dc_id: i32, is_media: bool, domains: &[String]) {
        let gen = self.current_generation;
        let target_key = DcTargetKey::new(dc_id, is_media);
        let mut set = std::collections::HashSet::with_capacity(domains.len());
        for d in domains {
            let norm = normalize_domain(d);
            if !norm.is_empty() {
                set.insert(norm);
            }
        }
        if set.is_empty() {
            self.in_flight_claims.remove(&(gen, target_key));
        } else {
            self.in_flight_claims.insert((gen, target_key), set);
        }
    }

    /// Splits Flowseal candidates for `(dc_id, is_media)` into 3 strict isolation tiers:
    /// 1. `exclusive_primary`: explicit pin, healthy non-colliding active domain, and this slot's
    ///    strictly disjoint shard (`idx % 10 == slot_idx`) not occupied by any other slot.
    /// 2. `unoccupied_overflow`: healthy unoccupied domains outside this slot's own shard (used
    ///    when the slot's own shard is empty/failing/429, or when the pool has < 10 domains),
    ///    followed by failing unoccupied domains.
    /// 3. `shared_fallback`: domains already occupied by other DC slots (used ONLY if zero
    ///    unoccupied non-429 domains exist anywhere).
    pub fn get_domains_for_dc_isolated_buckets(
        &self,
        dc_id: i32,
        is_media: bool,
        fallback_domains: &[String],
        pinned_domain: Option<&str>,
        reserved_by_others: &std::collections::HashSet<String>,
    ) -> IsolatedDomainCandidates {
        let mut out = IsolatedDomainCandidates::default();
        let mut seen = std::collections::HashSet::new();

        let gen = self.current_generation;
        let target_key = DcTargetKey::new(dc_id, is_media);
        let slot_idx = Self::dc_slot_rotation_index(dc_id, is_media);
        let stats_map = self.stats.get(&(gen, target_key));

        let mut occupied = self.other_occupied_domains(dc_id, is_media);
        for d in reserved_by_others {
            let norm = normalize_domain(d);
            if !norm.is_empty() {
                occupied.insert(norm);
            }
        }

        let is_failing = |dom: &str| -> bool {
            stats_map
                .and_then(|m| m.get(dom))
                .map(|s| s.consecutive_failures > 0)
                .unwrap_or(false)
        };
        let score_of = |dom: &str| -> u64 {
            stats_map
                .and_then(|m| m.get(dom))
                .map(|s| s.calculate_score())
                .unwrap_or(UNPROBED_DEFAULT_SCORE_MS)
        };

        // 1. Explicit pinned domain always leads exclusive_primary (unless failing, still primary so user pin is honored first).
        if let Some(pin_raw) = pinned_domain {
            let pin = normalize_domain(pin_raw);
            if !pin.is_empty() && seen.insert(pin.clone()) {
                out.exclusive_primary.push(pin);
            }
        }

        // 2. Current active domain for this slot (if not occupied by another slot and not failing).
        if let Some(active) = self.active_domains.get(&(gen, target_key)) {
            if !active.is_empty()
                && !seen.contains(active)
                && !occupied.contains(active)
                && !is_failing(active)
            {
                seen.insert(active.clone());
                out.exclusive_primary.push(active.clone());
            }
        }

        // Build deterministic sorted pool of all configured domains.
        let mut pool_domains: Vec<String> =
            Vec::with_capacity(self.domains.len() + fallback_domains.len());
        let mut pool_seen = std::collections::HashSet::new();
        for raw in self.domains.iter().chain(fallback_domains.iter()) {
            let norm = normalize_domain(raw);
            if !norm.is_empty() && pool_seen.insert(norm.clone()) {
                pool_domains.push(norm);
            }
        }
        pool_domains.sort();

        // Partition pool into this slot's disjoint shard (idx % 10 == slot_idx) and other shards.
        let mut own_shard_healthy: Vec<String> = Vec::new();
        let mut own_shard_failing: Vec<String> = Vec::new();
        let mut other_unoccupied_healthy: Vec<String> = Vec::new();
        let mut other_unoccupied_failing: Vec<String> = Vec::new();
        let mut shared_list: Vec<String> = Vec::new();

        for (idx, dom) in pool_domains.iter().enumerate() {
            if seen.contains(dom) {
                continue;
            }
            if occupied.contains(dom) {
                shared_list.push(dom.clone());
                continue;
            }
            let in_own_shard = idx % Self::ISOLATED_SLOT_COUNT == slot_idx;
            if in_own_shard {
                if is_failing(dom) {
                    own_shard_failing.push(dom.clone());
                } else {
                    own_shard_healthy.push(dom.clone());
                }
            } else if is_failing(dom) {
                other_unoccupied_failing.push(dom.clone());
            } else {
                other_unoccupied_healthy.push(dom.clone());
            }
        }

        // Include any ranked domains not present in `pool_domains`.
        if let Some(map) = stats_map {
            let mut extra: Vec<&String> = map.keys().filter(|d| !pool_seen.contains(*d)).collect();
            extra.sort();
            for dom in extra {
                if seen.contains(dom) {
                    continue;
                }
                if occupied.contains(dom) {
                    shared_list.push(dom.clone());
                } else if is_failing(dom) {
                    other_unoccupied_failing.push(dom.clone());
                } else {
                    other_unoccupied_healthy.push(dom.clone());
                }
            }
        }

        // Sort own shard by score (best first).
        own_shard_healthy.sort_by(|a, b| score_of(a).cmp(&score_of(b)).then_with(|| a.cmp(b)));
        for d in own_shard_healthy {
            if seen.insert(d.clone()) {
                out.exclusive_primary.push(d);
            }
        }

        // Rotate overflow pool deterministically by slot_idx, keeping ranked healthy domains ahead.
        if !other_unoccupied_healthy.is_empty() {
            let rot = slot_idx % other_unoccupied_healthy.len();
            other_unoccupied_healthy.rotate_left(rot);
            other_unoccupied_healthy.sort_by(|a, b| {
                let a_ranked = stats_map.map(|m| m.contains_key(a)).unwrap_or(false);
                let b_ranked = stats_map.map(|m| m.contains_key(b)).unwrap_or(false);
                match (a_ranked, b_ranked) {
                    (true, true) => score_of(a).cmp(&score_of(b)),
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    (false, false) => std::cmp::Ordering::Equal,
                }
            });
        }
        for d in other_unoccupied_healthy {
            if seen.insert(d.clone()) {
                out.unoccupied_overflow.push(d);
            }
        }

        // Failing unoccupied domains come after healthy unoccupied domains.
        own_shard_failing.sort_by(|a, b| score_of(a).cmp(&score_of(b)).then_with(|| a.cmp(b)));
        other_unoccupied_failing
            .sort_by(|a, b| score_of(a).cmp(&score_of(b)).then_with(|| a.cmp(b)));
        for d in own_shard_failing.into_iter().chain(other_unoccupied_failing) {
            if seen.insert(d.clone()) {
                out.unoccupied_overflow.push(d);
            }
        }

        // Shared fallback (only used if zero unoccupied candidates are eligible).
        shared_list.sort_by(|a, b| score_of(a).cmp(&score_of(b)).then_with(|| a.cmp(b)));
        for d in shared_list {
            if seen.insert(d.clone()) {
                out.shared_fallback.push(d);
            }
        }

        out
    }

    /// Flattened view of `get_domains_for_dc_isolated_buckets` (`exclusive_primary` ->
    /// `unoccupied_overflow` -> `shared_fallback`).
    pub fn get_domains_for_dc_isolated(
        &self,
        dc_id: i32,
        is_media: bool,
        fallback_domains: &[String],
        pinned_domain: Option<&str>,
        reserved_by_others: &std::collections::HashSet<String>,
    ) -> Vec<String> {
        let buckets = self.get_domains_for_dc_isolated_buckets(
            dc_id,
            is_media,
            fallback_domains,
            pinned_domain,
            reserved_by_others,
        );
        let mut all = Vec::with_capacity(
            buckets.exclusive_primary.len()
                + buckets.unoccupied_overflow.len()
                + buckets.shared_fallback.len(),
        );
        all.extend(buckets.exclusive_primary);
        all.extend(buckets.unoccupied_overflow);
        all.extend(buckets.shared_fallback);
        all
    }

    /// Claims `domain` as the active domain for `(dc_id, is_media)` if the slot currently has none
    /// and the domain is not already owned by another DC slot (when per-DC isolation is enabled).
    pub fn ensure_active_domain_if_unset(
        &mut self,
        dc_id: i32,
        is_media: bool,
        domain: &str,
    ) -> bool {
        let domain_norm = normalize_domain(domain);
        if domain_norm.is_empty() {
            return false;
        }
        let gen = self.current_generation;
        let target_key = DcTargetKey::new(dc_id, is_media);
        if let Some(cur) = self.active_domains.get(&(gen, target_key)) {
            if !cur.is_empty() {
                return false;
            }
        }
        if crate::config::is_flowseal_per_dc_enabled() {
            let own_pin = crate::config::get_flowseal_pinned_domain(dc_id, is_media);
            if own_pin.as_deref() != Some(domain_norm.as_str())
                && self.other_active_domains(dc_id, is_media).contains(&domain_norm)
            {
                return false;
            }
        }
        self.active_domains
            .insert((gen, target_key), domain_norm.clone());
        let mut single = std::collections::HashSet::with_capacity(1);
        single.insert(domain_norm.clone());
        self.in_flight_claims.insert((gen, target_key), single);
        let map = self.stats.entry((gen, target_key)).or_default();
        map.entry(domain_norm.clone())
            .or_insert_with(|| DomainStats::new(domain_norm));
        true
    }

    pub fn clear_active_domains(&mut self) {
        self.active_domains.clear();
        self.in_flight_claims.clear();
    }

    pub fn active_routes_snapshot(&self) -> Vec<(i32, bool, String)> {
        let gen = self.current_generation;
        let mut routes: Vec<(i32, bool, String)> = self
            .active_domains
            .iter()
            .filter_map(|((g, key), dom)| {
                if *g == gen && !dom.is_empty() {
                    Some((key.dc_id, key.is_media, dom.clone()))
                } else {
                    None
                }
            })
            .collect();
        routes.sort_by_key(|(dc, is_media, _)| (*dc, *is_media));
        routes
    }

    pub fn record_probe_rtt(
        &mut self,
        gen: u64,
        dc_id: i32,
        is_media: bool,
        domain: &str,
        latency_ms: u64,
    ) {
        let domain_norm = normalize_domain(domain);
        if domain_norm.is_empty() {
            return;
        }
        if gen != 0 && gen < self.current_generation {
            return; // Stale network event from prior generation
        }
        if gen > self.current_generation {
            self.notify_generation_change(gen);
        }

        let effective_gen = self.current_generation;
        let target_key = DcTargetKey::new(dc_id, is_media);

        let map = self.stats.entry((effective_gen, target_key)).or_default();
        let entry = map
            .entry(domain_norm.clone())
            .or_insert_with(|| DomainStats::new(domain_norm.clone()));

        match entry.probe_rtt_ms {
            Some(old_lat) => {
                entry.probe_rtt_ms = Some((old_lat * 7 + latency_ms * 3) / 10);
            }
            None => {
                entry.probe_rtt_ms = Some(latency_ms);
            }
        }

        self.recompute_active_domain_for_target(effective_gen, target_key);
    }

    /// Record verified useful RX on downstream bridge connection.
    /// Proves this domain successfully established end-to-end transport and received Telegram data.
    pub fn record_useful_success(
        &mut self,
        gen: u64,
        dc_id: i32,
        is_media: bool,
        domain: &str,
    ) {
        let domain_norm = normalize_domain(domain);
        if domain_norm.is_empty() {
            return;
        }
        if gen != 0 && gen < self.current_generation {
            return;
        }
        if gen > self.current_generation {
            self.notify_generation_change(gen);
        }

        let effective_gen = self.current_generation;
        let target_key = DcTargetKey::new(dc_id, is_media);

        let map = self.stats.entry((effective_gen, target_key)).or_default();
        let entry = map
            .entry(domain_norm.clone())
            .or_insert_with(|| DomainStats::new(domain_norm.clone()));

        entry.useful_success_count = entry.useful_success_count.saturating_add(1);
        entry.consecutive_failures = 0;

        self.recompute_active_domain_for_target(effective_gen, target_key);
    }

    /// Record connection failure, handshake timeout, or connection reset.
    pub fn record_failure(
        &mut self,
        gen: u64,
        dc_id: i32,
        is_media: bool,
        domain: &str,
    ) {
        let domain_norm = normalize_domain(domain);
        if domain_norm.is_empty() {
            return;
        }
        if gen != 0 && gen < self.current_generation {
            return;
        }
        if gen > self.current_generation {
            self.notify_generation_change(gen);
        }

        let effective_gen = self.current_generation;
        let target_key = DcTargetKey::new(dc_id, is_media);

        let map = self.stats.entry((effective_gen, target_key)).or_default();
        let entry = map
            .entry(domain_norm.clone())
            .or_insert_with(|| DomainStats::new(domain_norm.clone()));

        entry.failure_count = entry.failure_count.saturating_add(1);
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);

        if let Some(claims) = self.in_flight_claims.get_mut(&(effective_gen, target_key)) {
            claims.remove(&domain_norm);
        }

        self.recompute_active_domain_for_target(effective_gen, target_key);
    }

    pub fn reset_ranking(&mut self) {
        self.stats.clear();
        self.active_domains.clear();
        self.in_flight_claims.clear();
    }

    fn recompute_active_domain_for_target(&mut self, gen: u64, target_key: DcTargetKey) {
        let per_dc = crate::config::is_flowseal_per_dc_enabled();
        let mut occupied = if per_dc {
            let mut occ = self.other_occupied_domains(target_key.dc_id, target_key.is_media);
            for dom in crate::config::flowseal_pinned_domains_for_other_slots(
                target_key.dc_id,
                target_key.is_media,
            ) {
                occ.insert(dom);
            }
            occ
        } else {
            std::collections::HashSet::new()
        };
        let pinned_opt = if per_dc {
            crate::config::get_flowseal_pinned_domain(target_key.dc_id, target_key.is_media)
        } else {
            None
        };
        if let Some(ref pin) = pinned_opt {
            occupied.remove(pin);
        }

        let stats_map = match self.stats.get(&(gen, target_key)) {
            Some(m) if !m.is_empty() => m,
            _ => return,
        };

        let mut scored: Vec<(&String, u64, u32)> = stats_map
            .iter()
            .map(|(d, s)| (d, s.calculate_score(), s.consecutive_failures))
            .collect();
        scored.sort_by(|(da, sa, _), (db, sb, _)| sa.cmp(sb).then_with(|| da.cmp(db)));

        let chosen = if per_dc {
            if let Some(ref pin) = pinned_opt {
                if let Some((d, s, fails)) = scored.iter().find(|(d, _, _)| *d == pin) {
                    if *fails == 0 {
                        Some(((*d).clone(), *s))
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
            .or_else(|| {
                scored
                    .iter()
                    .find(|(d, _, fails)| *fails == 0 && !occupied.contains(*d))
                    .map(|(d, s, _)| ((*d).clone(), *s))
            })
            .or_else(|| {
                scored
                    .iter()
                    .find(|(d, _, _)| !occupied.contains(*d))
                    .map(|(d, s, _)| ((*d).clone(), *s))
            })
            .or_else(|| scored.first().map(|(d, s, _)| ((*d).clone(), *s)))
        } else {
            scored.first().map(|(d, s, _)| ((*d).clone(), *s))
        };

        let (best_domain, best_score) = match chosen {
            Some(pair) => pair,
            None => return,
        };

        let current_active = self.active_domains.get(&(gen, target_key)).cloned();
        let should_switch = match current_active {
            Some(ref cur) if !cur.is_empty() => match stats_map.get(cur) {
                Some(cur_stats) => {
                    if cur_stats.consecutive_failures > 0 {
                        // Current active domain experienced failure: failover immediately
                        true
                    } else if per_dc && occupied.contains(cur) && !occupied.contains(&best_domain) {
                        // Current active collides with another DC's active/pinned domain: isolate immediately
                        true
                    } else if per_dc
                        && pinned_opt.as_deref() == Some(best_domain.as_str())
                        && cur != &best_domain
                    {
                        true
                    } else {
                        let cur_score = cur_stats.calculate_score();
                        // Stability-First Hysteresis: only switch if the new winner is significantly better
                        cur_score > best_score + STABILITY_HYSTERESIS_MS
                    }
                }
                None => true,
            },
            _ => true,
        };

        if should_switch {
            self.active_domains.insert((gen, target_key), best_domain);
        }
    }

    pub fn get_status_json(&self) -> String {
        let gen = self.current_generation;
        let mut routes = Vec::new();

        let mut targets: Vec<DcTargetKey> = self
            .stats
            .keys()
            .filter_map(|(g, k)| if *g == gen { Some(*k) } else { None })
            .collect();

        for (g, k) in self.active_domains.keys() {
            if *g == gen && !targets.contains(k) {
                targets.push(*k);
            }
        }
        targets.sort_by_key(|k| (k.dc_id, k.is_media));

        for target in targets {
            let active_domain = self.active_domains.get(&(gen, target)).cloned();
            let mut rankings = Vec::new();
            if let Some(stats_map) = self.stats.get(&(gen, target)) {
                let mut list: Vec<&DomainStats> = stats_map.values().collect();
                list.sort_by_key(|s| s.calculate_score());
                for s in list {
                    rankings.push(RankedDomainSummary {
                        domain: s.domain.clone(),
                        probe_rtt_ms: s.probe_rtt_ms,
                        useful_success_count: s.useful_success_count,
                        failure_count: s.failure_count,
                        consecutive_failures: s.consecutive_failures,
                        score: s.calculate_score(),
                    });
                }
            }
            routes.push(TargetRouteStatus {
                dc_id: target.dc_id,
                is_media: target.is_media,
                active_domain,
                rankings,
            });
        }

        let status = DomainBalancerStatus {
            current_network_generation: gen,
            routes,
        };

        serde_json::to_string(&status).unwrap_or_else(|_| "{}".to_string())
    }

    /// Computes a lightweight cross-platform health summary for SLI telemetry.
    pub fn get_health_summary(&self) -> BalancerHealthSummary {
        let gen = self.current_generation;
        let active_domain = self
            .active_domains
            .get(&(gen, DcTargetKey::new(2, false)))
            .cloned()
            .or_else(|| {
                self.active_domains
                    .iter()
                    .find(|((g, _), _)| *g == gen)
                    .map(|(_, d)| d.clone())
            });

        let mut per_domain: HashMap<String, (Option<u64>, u64, u64, u32)> = HashMap::new();
        for ((g, _), map) in &self.stats {
            if *g != gen {
                continue;
            }
            for (dom, st) in map {
                let entry = per_domain.entry(dom.clone()).or_insert((None, 0, 0, 0));
                if let Some(rtt) = st.probe_rtt_ms {
                    entry.0 = Some(entry.0.map_or(rtt, |cur| cur.min(rtt)));
                }
                entry.1 = entry.1.saturating_add(st.useful_success_count);
                entry.2 = entry.2.saturating_add(st.failure_count);
                entry.3 = entry.3.max(st.consecutive_failures);
            }
        }

        let total_domain_count = per_domain.len().max(self.domains.len());
        let mut healthy_domain_count = 0usize;
        let mut rtts: Vec<u64> = Vec::new();
        let mut total_useful_success_count = 0u64;
        let mut total_failure_count = 0u64;

        for (_dom, (rtt_opt, useful, fails, consec)) in per_domain {
            total_useful_success_count = total_useful_success_count.saturating_add(useful);
            total_failure_count = total_failure_count.saturating_add(fails);
            if consec == 0 && (rtt_opt.is_some() || useful > 0) {
                healthy_domain_count += 1;
            }
            if consec == 0 {
                if let Some(r) = rtt_opt {
                    if r > 0 {
                        rtts.push(r);
                    }
                }
            }
        }
        rtts.sort_unstable();
        let min_probe_rtt_ms = rtts.first().copied();
        let median_probe_rtt_ms = if rtts.is_empty() {
            None
        } else {
            Some(rtts[rtts.len() / 2])
        };

        BalancerHealthSummary {
            active_domain,
            healthy_domain_count,
            total_domain_count,
            min_probe_rtt_ms,
            median_probe_rtt_ms,
            total_useful_success_count,
            total_failure_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_normalization() {
        assert_eq!(normalize_domain("kws2.worker1.dev"), "worker1.dev");
        assert_eq!(normalize_domain("kws2-1.worker1.dev"), "worker1.dev");
        assert_eq!(normalize_domain("kws4.worker2.dev:443"), "worker2.dev");
        assert_eq!(normalize_domain("kws4-1.worker2.dev:443"), "worker2.dev");
        assert_eq!(
            normalize_domain("https://kws203.edge.worker.dev/apiws"),
            "edge.worker.dev"
        );
        assert_eq!(normalize_domain("worker3.dev"), "worker3.dev");
    }

    #[test]
    fn promoted_anycast_candidate_is_prioritized_for_its_dc_only() {
        let mut balancer = Balancer::new();
        balancer.update_domains_list(&["fallback.example".to_string()]);

        assert!(balancer.update_domain_for_dc(2, false, "kws2.fast.example:443"));

        assert_eq!(
            balancer.get_domains_for_dc(2, false).first().map(String::as_str),
            Some("fast.example")
        );
        assert!(!balancer.get_domains_for_dc(4, false).contains(&"fast.example".to_string()));
    }

    #[test]
    fn test_balancer_per_dc_isolation_no_leakage_from_dc2() {
        let mut b = Balancer::new();
        let domains = vec![
            "worker1.dev".to_string(),
            "worker2.dev".to_string(),
            "worker3.dev".to_string(),
        ];
        b.update_domains_list(&domains);

        // Rank DC2: worker1 is fastest (30ms)
        b.update_ranked_domains_for_dc(
            2,
            false,
            vec![
                ("worker1.dev".to_string(), 30),
                ("worker2.dev".to_string(), 100),
            ],
        );

        assert_eq!(
            b.get_fastest_domain_for_dc(2, false).as_deref(),
            Some("worker1.dev")
        );

        // MOB-026: DC4 is unprobed. It MUST NOT inherit worker1 from DC2!
        assert_eq!(b.get_fastest_domain_for_dc(4, false), None);

        // Rank DC4 explicitly: worker3 is fastest (20ms)
        b.update_ranked_domains_for_dc(
            4,
            false,
            vec![
                ("worker3.dev".to_string(), 20),
                ("worker2.dev".to_string(), 80),
            ],
        );

        assert_eq!(
            b.get_fastest_domain_for_dc(4, false).as_deref(),
            Some("worker3.dev")
        );
        // DC2 winner is still worker1.dev
        assert_eq!(
            b.get_fastest_domain_for_dc(2, false).as_deref(),
            Some("worker1.dev")
        );
    }

    #[test]
    fn test_balancer_media_class_separation() {
        let mut b = Balancer::new();
        let domains = vec!["worker1.dev".to_string(), "worker2.dev".to_string()];
        b.update_domains_list(&domains);

        // DC2 Chat (is_media = false): worker1 is fastest
        b.update_ranked_domains_for_dc(
            2,
            false,
            vec![
                ("worker1.dev".to_string(), 40),
                ("worker2.dev".to_string(), 120),
            ],
        );

        // DC2 Media (is_media = true): worker2 is fastest
        b.update_ranked_domains_for_dc(
            2,
            true,
            vec![
                ("worker2.dev".to_string(), 25),
                ("worker1.dev".to_string(), 150),
            ],
        );

        // Chat uses worker1, Media uses worker2!
        assert_eq!(
            b.get_fastest_domain_for_dc(2, false).as_deref(),
            Some("worker1.dev")
        );
        assert_eq!(
            b.get_fastest_domain_for_dc(2, true).as_deref(),
            Some("worker2.dev")
        );
    }

    #[test]
    fn test_balancer_network_generation_change_does_not_inherit_bad_winner() {
        let mut b = Balancer::new();
        b.set_network_generation(1);

        // On generation 1: worker_bad was assigned/active on DC2
        b.update_domain_for_dc(2, false, "worker_bad.dev");
        assert_eq!(
            b.get_active_domain_for_dc(2, false).as_deref(),
            Some("worker_bad.dev")
        );

        // Network handover (generation 1 -> generation 2)
        b.set_network_generation(2);

        // On generation 2: bad winner from generation 1 is NOT inherited!
        assert_eq!(b.get_active_domain_for_dc(2, false), None);
        assert_eq!(b.get_fastest_domain_for_dc(2, false), None);
    }

    #[test]
    fn test_balancer_useful_success_improves_score_and_overtakes_probe() {
        let mut b = Balancer::new();
        let gen = 1;
        b.set_network_generation(gen);

        // workerA has 60ms probe RTT, 0 useful successes -> score = 60
        b.record_probe_rtt(gen, 2, false, "workerA.dev", 60);

        // workerB has 80ms probe RTT
        b.record_probe_rtt(gen, 2, false, "workerB.dev", 80);

        // Initially workerA is active (60ms vs 80ms)
        assert_eq!(
            b.get_fastest_domain_for_dc(2, false).as_deref(),
            Some("workera.dev")
        );

        // Now workerB achieves multiple confirmed useful RX (4 * 15 = 60ms bonus)
        // workerB score becomes: 80 - 60 = 20ms
        for _ in 0..4 {
            b.record_useful_success(gen, 2, false, "workerB.dev");
        }

        // workerB (score 20) now beats workerA (score 60) by 40ms (> hysteresis threshold when combined)
        // If workerB has useful success and lower score, workerB overtakes workerA
        // 60 > 20 + 60 is false (40 <= 60), but with 1 more useful success or failure on A:
        b.record_useful_success(gen, 2, false, "workerB.dev");

        // If workerA experiences a single failure:
        b.record_failure(gen, 2, false, "workerA.dev");

        // workerA score jumped from 60 to 60 + 100 + 20 = 180!
        // workerB score is 20. Failover happens immediately!
        assert_eq!(
            b.get_fastest_domain_for_dc(2, false).as_deref(),
            Some("workerb.dev")
        );
    }

    #[test]
    fn test_balancer_status_json() {
        let mut b = Balancer::new();
        b.set_network_generation(3);
        b.record_probe_rtt(3, 2, false, "worker1.dev", 45);
        b.record_useful_success(3, 2, false, "worker1.dev");
        b.record_probe_rtt(3, 4, true, "worker2.dev", 25);

        let json = b.get_status_json();
        assert!(json.contains("\"current_network_generation\":3"));
        assert!(json.contains("\"dc_id\":2"));
        assert!(json.contains("\"is_media\":false"));
        assert!(json.contains("\"dc_id\":4"));
        assert!(json.contains("\"is_media\":true"));
        assert!(json.contains("\"worker1.dev\""));
        assert!(json.contains("\"worker2.dev\""));
    }

    #[test]
    fn test_balancer_isolated_cold_start_assigns_distinct_domains_across_dcs() {
        let mut b = Balancer::new();
        let domains: Vec<String> = (1..=10).map(|i| format!("cdn{:02}.co.uk", i)).collect();
        b.update_domains_list(&domains);

        let empty_reserved = std::collections::HashSet::new();
        let slots = [(1, false), (2, false), (2, true), (4, true), (5, false)];
        let mut chosen = std::collections::HashSet::new();

        for (dc, is_media) in slots {
            let candidates =
                b.get_domains_for_dc_isolated(dc, is_media, &domains, None, &empty_reserved);
            let primary = candidates.first().expect("non-empty candidates").clone();
            assert!(
                chosen.insert(primary.clone()),
                "slot DC{} media={} collided on {}",
                dc,
                is_media,
                primary
            );
            b.ensure_active_domain_if_unset(dc, is_media, &primary);
        }
        assert_eq!(chosen.len(), slots.len());
    }

    #[test]
    fn test_balancer_isolated_respects_pins_other_active_and_small_pool_fallback() {
        let mut b = Balancer::new();
        let domains = vec![
            "a.co.uk".to_string(),
            "b.co.uk".to_string(),
            "c.co.uk".to_string(),
        ];
        b.update_domains_list(&domains);

        // DC2 claims a.co.uk; DC4 pins b.co.uk.
        b.update_domain_for_dc(2, false, "a.co.uk");
        let mut reserved = std::collections::HashSet::new();
        reserved.insert("b.co.uk".to_string());

        // DC5 should lead with c.co.uk (only unoccupied domain) and keep a/b as fallback tail.
        let dc5 = b.get_domains_for_dc_isolated(5, false, &domains, None, &reserved);
        assert_eq!(dc5.first().map(String::as_str), Some("c.co.uk"));
        assert_eq!(dc5.len(), 3);

        // Explicit pin for DC4 always leads even when ranked stats favor another domain.
        let dc4 = b.get_domains_for_dc_isolated(4, true, &domains, Some("b.co.uk"), &std::collections::HashSet::new());
        assert_eq!(dc4.first().map(String::as_str), Some("b.co.uk"));

        // Small pool (2 domains, 3 DCs): 3rd DC still receives fallback candidates.
        let mut small = Balancer::new();
        let two = vec!["x.co.uk".to_string(), "y.co.uk".to_string()];
        small.update_domains_list(&two);
        small.update_domain_for_dc(2, false, "x.co.uk");
        small.update_domain_for_dc(4, true, "y.co.uk");
        let dc1 = small.get_domains_for_dc_isolated(
            1,
            false,
            &two,
            None,
            &std::collections::HashSet::new(),
        );
        assert_eq!(dc1.len(), 2);
    }
}
