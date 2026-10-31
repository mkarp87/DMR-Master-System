use dmr_core::{Bridge, BridgeMember, TalkgroupId, TimeoutPolicy, Timeslot};
use std::{collections::HashMap, time::{Duration, Instant}};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteKey {
    pub endpoint: String,
    pub slot: Timeslot,
    pub talkgroup: TalkgroupId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteTarget {
    pub endpoint: String,
    pub slot: Timeslot,
    pub talkgroup: TalkgroupId,
    pub bridge: String,
}

#[derive(Debug, Clone)]
struct MemberState {
    member: BridgeMember,
    active: bool,
    last_changed: Instant,
}

#[derive(Debug, Clone)]
struct BridgeState {
    name: String,
    members: Vec<MemberState>,
}

#[derive(Debug, Clone)]
pub struct RouteEngine {
    bridges: Vec<BridgeState>,
    static_routes: usize,
}

impl RouteEngine {
    pub fn compile(bridges: &[Bridge]) -> Self {
        let now = Instant::now();
        let mut static_routes = 0usize;
        let states = bridges
            .iter()
            .map(|bridge| {
                let active_count = bridge.members.iter().filter(|m| m.initially_active).count();
                static_routes += active_count.saturating_mul(active_count.saturating_sub(1));
                BridgeState {
                    name: bridge.name.clone(),
                    members: bridge
                        .members
                        .iter()
                        .cloned()
                        .map(|member| MemberState {
                            active: member.initially_active,
                            member,
                            last_changed: now,
                        })
                        .collect(),
                }
            })
            .collect();
        Self { bridges: states, static_routes }
    }

    pub fn len(&self) -> usize {
        self.static_routes
    }

    pub fn is_empty(&self) -> bool {
        self.bridges.is_empty()
    }

    pub fn route_group(
        &mut self,
        endpoint: &str,
        slot: Timeslot,
        talkgroup: TalkgroupId,
        now: Instant,
    ) -> Vec<RouteTarget> {
        self.apply_timeouts(now);
        self.apply_controls(endpoint, slot, talkgroup, now);

        let mut out = Vec::new();
        for bridge in &mut self.bridges {
            let mut source_matches = false;
            for state in &mut bridge.members {
                if state.active
                    && state.member.endpoint == endpoint
                    && state.member.timeslot == slot
                    && state.member.talkgroup == talkgroup
                {
                    source_matches = true;
                    if state.member.timeout_policy == TimeoutPolicy::On
                        && state.member.timeout_secs > 0
                    {
                        // ON timers represent inactivity: matching traffic refreshes the timer.
                        state.last_changed = now;
                    }
                }
            }
            if !source_matches {
                continue;
            }

            for target in &bridge.members {
                if !target.active {
                    continue;
                }
                if target.member.endpoint == endpoint
                    && target.member.timeslot == slot
                    && target.member.talkgroup == talkgroup
                {
                    continue;
                }
                let candidate = RouteTarget {
                    endpoint: target.member.endpoint.clone(),
                    slot: target.member.timeslot,
                    talkgroup: target.member.talkgroup,
                    bridge: bridge.name.clone(),
                };
                if !out.contains(&candidate) {
                    out.push(candidate);
                }
            }
        }
        out
    }

    fn apply_controls(
        &mut self,
        endpoint: &str,
        slot: Timeslot,
        talkgroup: TalkgroupId,
        now: Instant,
    ) {
        for bridge in &mut self.bridges {
            for state in &mut bridge.members {
                if state.member.endpoint != endpoint || state.member.timeslot != slot {
                    continue;
                }
                if state.member.on.contains(&talkgroup) {
                    state.active = true;
                    state.last_changed = now;
                }
                if state.member.off.contains(&talkgroup) {
                    state.active = false;
                    state.last_changed = now;
                }
                if state.member.reset.contains(&talkgroup) {
                    state.active = state.member.initially_active;
                    state.last_changed = now;
                }
            }
        }
    }

    fn apply_timeouts(&mut self, now: Instant) {
        for bridge in &mut self.bridges {
            for state in &mut bridge.members {
                if state.member.timeout_secs == 0 {
                    continue;
                }
                let elapsed = now.saturating_duration_since(state.last_changed);
                if elapsed < Duration::from_secs(state.member.timeout_secs) {
                    continue;
                }
                match state.member.timeout_policy {
                    TimeoutPolicy::None => {}
                    TimeoutPolicy::On => {
                        if state.active {
                            state.active = false;
                            state.last_changed = now;
                        }
                    }
                    TimeoutPolicy::Off => {
                        if !state.active {
                            state.active = true;
                            state.last_changed = now;
                        }
                    }
                }
            }
        }
    }

    pub fn bridge_status(&self) -> Vec<BridgeStatus> {
        self.bridges
            .iter()
            .map(|bridge| BridgeStatus {
                name: bridge.name.clone(),
                members: bridge
                    .members
                    .iter()
                    .map(|state| MemberStatus {
                        endpoint: state.member.endpoint.clone(),
                        slot: state.member.timeslot,
                        talkgroup: state.member.talkgroup,
                        active: state.active,
                    })
                    .collect(),
            })
            .collect()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BridgeStatus {
    pub name: String,
    pub members: Vec<MemberStatus>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MemberStatus {
    pub endpoint: String,
    pub slot: Timeslot,
    pub talkgroup: TalkgroupId,
    pub active: bool,
}

/// Immutable lookup retained for compatibility and simple callers.
#[derive(Debug, Default, Clone)]
pub struct RouteTable {
    routes: HashMap<RouteKey, Vec<RouteTarget>>,
}

impl RouteTable {
    pub fn compile(bridges: &[Bridge]) -> Self {
        let mut table = Self::default();
        for bridge in bridges {
            let active: Vec<&BridgeMember> = bridge.members.iter().filter(|m| m.initially_active).collect();
            for source in &active {
                let key = RouteKey {
                    endpoint: source.endpoint.clone(),
                    slot: source.timeslot,
                    talkgroup: source.talkgroup,
                };
                let out = table.routes.entry(key).or_default();
                for target in &active {
                    if source.endpoint == target.endpoint
                        && source.timeslot == target.timeslot
                        && source.talkgroup == target.talkgroup
                    {
                        continue;
                    }
                    let candidate = RouteTarget {
                        endpoint: target.endpoint.clone(),
                        slot: target.timeslot,
                        talkgroup: target.talkgroup,
                        bridge: bridge.name.clone(),
                    };
                    if !out.contains(&candidate) {
                        out.push(candidate);
                    }
                }
            }
        }
        table
    }

    pub fn lookup(&self, endpoint: &str, slot: Timeslot, tg: TalkgroupId) -> &[RouteTarget] {
        static EMPTY: [RouteTarget; 0] = [];
        self.routes
            .get(&RouteKey { endpoint: endpoint.into(), slot, talkgroup: tg })
            .map(Vec::as_slice)
            .unwrap_or(&EMPTY)
    }

    pub fn len(&self) -> usize { self.routes.len() }
    pub fn is_empty(&self) -> bool { self.routes.is_empty() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(e: &str, s: Timeslot, tg: u32) -> BridgeMember {
        BridgeMember {
            endpoint: e.into(),
            timeslot: s,
            talkgroup: TalkgroupId(tg),
            initially_active: true,
            timeout_secs: 0,
            timeout_policy: TimeoutPolicy::None,
            on: vec![],
            off: vec![],
            reset: vec![],
        }
    }

    #[test]
    fn compiles_tg_and_slot_translation() {
        let b = Bridge { name: "x".into(), members: vec![m("A", Timeslot::One, 1001), m("B", Timeslot::Two, 2001)] };
        let t = RouteTable::compile(&[b]);
        let out = t.lookup("A", Timeslot::One, TalkgroupId(1001));
        assert_eq!(out[0].endpoint, "B");
        assert_eq!(out[0].slot, Timeslot::Two);
        assert_eq!(out[0].talkgroup, TalkgroupId(2001));
    }

    #[test]
    fn dynamic_on_off_and_reset_controls_work() {
        let mut a = m("A", Timeslot::One, 1001);
        a.on = vec![TalkgroupId(5000)];
        a.off = vec![TalkgroupId(4000)];
        a.reset = vec![TalkgroupId(9999)];
        let b = Bridge { name: "x".into(), members: vec![a, m("B", Timeslot::One, 1001)] };
        let mut engine = RouteEngine::compile(&[b]);
        let now = Instant::now();
        assert_eq!(engine.route_group("A", Timeslot::One, TalkgroupId(1001), now).len(), 1);
        engine.route_group("A", Timeslot::One, TalkgroupId(4000), now);
        assert!(engine.route_group("A", Timeslot::One, TalkgroupId(1001), now).is_empty());
        engine.route_group("A", Timeslot::One, TalkgroupId(5000), now);
        assert_eq!(engine.route_group("A", Timeslot::One, TalkgroupId(1001), now).len(), 1);
    }
}
