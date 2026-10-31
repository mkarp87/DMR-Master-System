use dmr_core::{Bridge, BridgeMember, TalkgroupId, Timeslot};
use std::collections::HashMap;

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
}

#[derive(Debug, Default, Clone)]
pub struct RouteTable {
    routes: HashMap<RouteKey, Vec<RouteTarget>>,
}

impl RouteTable {
    pub fn compile(bridges: &[Bridge]) -> Self {
        let mut table = Self::default();
        for bridge in bridges {
            let active: Vec<&BridgeMember> = bridge
                .members
                .iter()
                .filter(|m| m.initially_active)
                .collect();
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
            .get(&RouteKey {
                endpoint: endpoint.into(),
                slot,
                talkgroup: tg,
            })
            .map(Vec::as_slice)
            .unwrap_or(&EMPTY)
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmr_core::TimeoutPolicy;
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
        let b = Bridge {
            name: "x".into(),
            members: vec![m("A", Timeslot::One, 1001), m("B", Timeslot::Two, 2001)],
        };
        let t = RouteTable::compile(&[b]);
        let out = t.lookup("A", Timeslot::One, TalkgroupId(1001));
        assert_eq!(out[0].endpoint, "B");
        assert_eq!(out[0].slot, Timeslot::Two);
        assert_eq!(out[0].talkgroup, TalkgroupId(2001));
    }
}
