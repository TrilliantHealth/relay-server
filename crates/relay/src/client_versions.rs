//! Plugin version per Yjs client id, for annotating logs and gating access.
//!
//! Two sources, by strength:
//!
//! - **Declared**: the client's own statement of its id-version binding,
//!   via either the `cid` upgrade query param (binding the id to the
//!   connection's `v` param) or a `relayVersion` field inside its awareness
//!   state payload. Minted by the id's owner, so it stays correct no matter
//!   who relays it. Overrides everything.
//! - **Inferred**: the `v` query param of the connection that *introduced*
//!   the id - the first live (non-null, solo) awareness entry the server has
//!   ever seen for it. An echo can only echo what the server already
//!   broadcast, so the first introduction is causally the owner's own
//!   connection. Immutable once set (an id is one session on one build), and
//!   rendered with a `~` prefix so its weaker provenance is visible.
//!
//! Nothing else may feed this. Binding transport facts to the ids embedded in
//! *updates* stamped the deliverer's version onto the minter (one resync
//! re-stamped ~4,300 ids), and non-first awareness entries can be echoes.
//!
//! Ephemeral by design: versions describe live clients, so a restart forgets
//! them - at the cost that sessions which re-introduce their ids inside
//! full-map relays after a restart stay unversioned until they declare.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

pub const UNKNOWN: &str = "-";

#[derive(Default)]
struct _State {
    declared: HashMap<u64, String>,
    inferred: HashMap<u64, String>,
    seen: HashSet<u64>,
}

pub struct Observation<'a> {
    pub client_id: u64,
    pub declared: Option<&'a str>,
    pub solo_live: bool,
    pub connection_version: Option<&'a str>,
}

pub struct Recorded {
    pub version: String,
    pub previous: Option<String>,
}

#[derive(Default)]
pub struct ClientVersions {
    state: RwLock<_State>,
}

impl ClientVersions {
    pub fn new() -> Self {
        Self::default()
    }

    fn _declare(state: &mut _State, client_id: u64, version: &str) -> Option<Recorded> {
        let previous = state.declared.insert(client_id, version.to_string());
        if previous.as_deref() == Some(version) {
            return None;
        }

        Some(Recorded {
            version: version.to_string(),
            previous,
        })
    }

    pub fn declare(&self, client_id: u64, version: &str) -> Option<Recorded> {
        let mut state = self.state.write().unwrap();
        state.seen.insert(client_id);
        Self::_declare(&mut state, client_id, version)
    }

    pub fn observe(&self, observation: Observation) -> Option<Recorded> {
        let mut state = self.state.write().unwrap();
        let never_seen = state.seen.insert(observation.client_id);

        if let Some(declared) = observation.declared {
            return Self::_declare(&mut state, observation.client_id, declared);
        }

        if !(observation.solo_live && never_seen) {
            return None;
        }
        let version = observation.connection_version?;

        state
            .inferred
            .insert(observation.client_id, version.to_string());
        Some(Recorded {
            version: format!("~{version}"),
            previous: None,
        })
    }

    fn _lookup(state: &_State, client_id: u64) -> Option<String> {
        if let Some(declared) = state.declared.get(&client_id) {
            return Some(declared.clone());
        }

        state
            .inferred
            .get(&client_id)
            .map(|version| format!("~{version}"))
    }

    pub fn describe(&self, client_ids: &[u64]) -> String {
        let state = self.state.read().unwrap();
        let mut versions: Vec<String> = client_ids
            .iter()
            .filter_map(|client_id| Self::_lookup(&state, *client_id))
            .collect();
        versions.sort_unstable();
        versions.dedup();

        if versions.is_empty() {
            return UNKNOWN.to_string();
        }

        versions.join(",")
    }

    pub fn snapshot(&self) -> Vec<(u64, String)> {
        let state = self.state.read().unwrap();
        let mut entries: Vec<(u64, String)> = state
            .declared
            .keys()
            .chain(state.inferred.keys())
            .filter_map(|client_id| {
                Self::_lookup(&state, *client_id).map(|version| (*client_id, version))
            })
            .collect();
        entries.sort_unstable_by_key(|(client_id, _)| *client_id);
        entries.dedup_by_key(|(client_id, _)| *client_id);
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declared(client_id: u64, version: &str) -> Observation<'_> {
        Observation {
            client_id,
            declared: Some(version),
            solo_live: true,
            connection_version: None,
        }
    }

    fn introduced(client_id: u64, connection_version: &str) -> Observation<'_> {
        Observation {
            client_id,
            declared: None,
            solo_live: true,
            connection_version: Some(connection_version),
        }
    }

    #[test]
    fn a_declared_version_reports_bare() {
        let versions = ClientVersions::new();
        versions.observe(declared(1, "0.9.1"));

        assert_eq!(versions.describe(&[1]), "0.9.1");
    }

    #[test]
    fn a_first_introduction_infers_with_visible_provenance() {
        let versions = ClientVersions::new();
        versions.observe(introduced(1, "0.9.0"));

        assert_eq!(versions.describe(&[1]), "~0.9.0");
    }

    #[test]
    fn an_echo_after_introduction_cannot_rebind() {
        let versions = ClientVersions::new();
        versions.observe(introduced(1, "0.9.0"));
        assert!(versions.observe(introduced(1, "0.8.8")).is_none());

        assert_eq!(versions.describe(&[1]), "~0.9.0");
    }

    #[test]
    fn an_id_first_seen_in_a_relay_is_never_inferable() {
        let versions = ClientVersions::new();
        versions.observe(Observation {
            client_id: 1,
            declared: None,
            solo_live: false,
            connection_version: Some("0.9.0"),
        });
        assert!(versions.observe(introduced(1, "0.9.0")).is_none());

        assert_eq!(versions.describe(&[1]), UNKNOWN);
    }

    #[test]
    fn a_declaration_overrides_an_inference() {
        let versions = ClientVersions::new();
        versions.observe(introduced(1, "0.9.0"));
        versions.observe(declared(1, "0.9.1"));

        assert_eq!(versions.describe(&[1]), "0.9.1");
    }

    #[test]
    fn an_inference_never_overrides_a_declaration() {
        let versions = ClientVersions::new();
        versions.observe(declared(1, "0.9.1"));
        versions.observe(introduced(1, "0.8.8"));

        assert_eq!(versions.describe(&[1]), "0.9.1");
    }

    #[test]
    fn a_connection_without_a_version_cannot_infer() {
        let versions = ClientVersions::new();
        assert!(versions
            .observe(Observation {
                client_id: 1,
                declared: None,
                solo_live: true,
                connection_version: None,
            })
            .is_none());

        assert_eq!(versions.describe(&[1]), UNKNOWN);
    }

    #[test]
    fn repeated_declarations_log_once() {
        let versions = ClientVersions::new();
        assert!(versions.observe(declared(1, "0.9.1")).is_some());
        assert!(versions.observe(declared(1, "0.9.1")).is_none());
    }

    #[test]
    fn a_merged_update_across_builds_names_both() {
        let versions = ClientVersions::new();
        versions.observe(declared(1, "0.8.9"));
        versions.observe(introduced(2, "0.9.0"));

        assert_eq!(versions.describe(&[1, 2]), "0.8.9,~0.9.0");
    }

    #[test]
    fn unrecorded_clients_do_not_mask_a_known_one() {
        let versions = ClientVersions::new();
        versions.observe(declared(1, "0.9.1"));

        assert_eq!(versions.describe(&[1, 999]), "0.9.1");
    }

    #[test]
    fn no_clients_at_all_reads_as_unknown() {
        let versions = ClientVersions::new();

        assert_eq!(versions.describe(&[]), UNKNOWN);
    }

    #[test]
    fn a_pre_joined_declaration_reports_bare() {
        let versions = ClientVersions::new();
        versions.declare(1, "0.9.1");

        assert_eq!(versions.describe(&[1]), "0.9.1");
    }

    #[test]
    fn a_pre_joined_declaration_blocks_later_inference() {
        let versions = ClientVersions::new();
        versions.declare(1, "0.9.1");
        assert!(versions.observe(introduced(1, "0.8.8")).is_none());

        assert_eq!(versions.describe(&[1]), "0.9.1");
    }

    #[test]
    fn a_matching_payload_declaration_after_a_pre_join_logs_nothing() {
        let versions = ClientVersions::new();
        assert!(versions.declare(1, "0.9.1").is_some());
        assert!(versions.observe(declared(1, "0.9.1")).is_none());
    }

    #[test]
    fn a_snapshot_lists_both_sources_in_id_order() {
        let versions = ClientVersions::new();
        versions.observe(introduced(20, "0.9.0"));
        versions.observe(declared(10, "0.9.1"));

        assert_eq!(
            versions.snapshot(),
            vec![(10, "0.9.1".to_string()), (20, "~0.9.0".to_string()),]
        );
    }
}
