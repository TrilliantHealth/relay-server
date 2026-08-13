//! Identify who produced an update.
//!
//! The event callback's captured user describes whichever connection first
//! loaded the doc, not the edit in hand, so it reads `-` forever on any doc
//! first opened without a user token. The doc itself holds the truth:
//! `register_new_client_ids` records client_id -> user in the PermanentUserData
//! `users` map from each connection's authenticated identity, and an update
//! names the clients it came from.
//!
//! Two traps in reading those client ids, both of which fail by reporting no
//! author rather than a wrong one:
//!
//! 1. Use `Update::state_vector_lower`, never `state_vector`. The latter is an
//!    upper bound over blocks contiguous from clock 0, so it drops any client
//!    whose first block in the update has a nonzero clock - which is every
//!    update after a client's first. It looks correct against a freshly-created
//!    test doc and returns empty for most real traffic.
//! 2. Insertions and deletions live in different places. A deletion creates no
//!    blocks, so a delete-only update has an empty state vector by any measure
//!    and is attributable only through `delete_set`.

use crate::attributed_content::user_by_client;
use std::collections::HashSet;
use yrs::updates::decoder::Decode;
use yrs::{ReadTxn, Transact, Update};

/// Every client that contributed to `update`, whether by inserting or deleting.
///
/// Deletions are the reason both sources are needed: removing a map entry adds
/// ranges to the delete set and creates no blocks at all, so an update that only
/// deletes has an empty state vector and is attributable solely through
/// `delete_set`. Folder membership removals are exactly that shape.
fn _clients_in(update: &Update) -> HashSet<u64> {
    update
        .state_vector_lower()
        .iter()
        .map(|(client_id, _)| client_id.get())
        .chain(
            update
                .delete_set()
                .iter()
                .map(|(client_id, _)| client_id.get()),
        )
        .collect()
}

/// The user behind `update`, resolved through the doc's PUD map.
///
/// Returns None when the update names no client we have an identity for, which
/// covers server-authored updates and clients that connected before their user
/// was registered. Multiple distinct users means a merged update that no single
/// person authored, so it reports none rather than picking one arbitrarily.
pub fn user_for_update<T: ReadTxn>(txn: &T, update: &[u8]) -> Option<String> {
    let clients = _clients_in(&Update::decode_v1(update).ok()?);
    let by_client = user_by_client(txn);

    let users: HashSet<&String> = clients
        .iter()
        .filter_map(|client_id| by_client.get(client_id))
        .collect();

    match users.len() {
        1 => users.into_iter().next().cloned(),
        _ => None,
    }
}

/// The yjs client ids an update came from, ascending.
///
/// A user has one client id per device and session (PUD stores `ids` as an
/// array), so this is what distinguishes "their laptop" from "their phone" when
/// the same person appears to do something twice - and what keys anything
/// describing the client rather than the person, such as its plugin version.
pub fn clients_in_update(update: &[u8]) -> Vec<u64> {
    let Ok(decoded) = Update::decode_v1(update) else {
        return Vec::new();
    };

    let mut ids: Vec<u64> = _clients_in(&decoded).into_iter().collect();
    ids.sort_unstable();
    ids
}

/// True when every client in the update is server-authored (53-bit yrs id,
/// ≥ 2^32). PUD registration writes are the main case: the server mutates
/// the doc's `users` map under its own client id, which fires
/// `observe_update_v1` and would otherwise log a `Doc edited` line for
/// internal bookkeeping that no human produced.
pub fn is_server_only_update(update: &[u8]) -> bool {
    let Ok(decoded) = Update::decode_v1(update) else {
        return false;
    };

    let ids = _clients_in(&decoded);
    !ids.is_empty() && ids.iter().all(|id| *id >= (1u64 << 32))
}

/// The same client ids, comma-separated, or "-" when the update names none.
pub fn clients_for_update(update: &[u8]) -> String {
    let ids = clients_in_update(update);
    if ids.is_empty() {
        return "-".to_string();
    }

    ids.iter().map(u64::to_string).collect::<Vec<_>>().join(",")
}

/// Same lookup, reading the PUD map out of the post-update snapshot the event
/// carries. Update callbacks fire while the edited doc's awareness lock is held
/// as a writer, so the live doc is not readable from there.
pub fn user_from_snapshot(snapshot: &[u8], update: &[u8]) -> Option<String> {
    let doc = yrs::Doc::new();
    {
        let mut txn = doc.transact_mut();
        txn.apply_update(Update::decode_v1(snapshot).ok()?).ok()?;
    }

    let txn = doc.transact();
    user_for_update(&txn, update)
}

#[cfg(test)]
mod tests {
    use super::*;
    use yrs::{Array, Map, Text, Transact};

    /// Mirror of the PUD shape `register_new_client_ids` writes:
    /// `users[user_id] = { ids: [client_id, ...] }`.
    fn register(doc: &yrs::Doc, user_id: &str, client_ids: &[u64]) {
        let users = doc.get_or_insert_map("users");
        let mut txn = doc.transact_mut();
        let entry = users.insert(&mut txn, user_id, yrs::MapPrelim::default());
        let ids = entry.insert(&mut txn, "ids", yrs::ArrayPrelim::default());
        for cid in client_ids {
            ids.push_back(&mut txn, *cid as f64);
        }
    }

    /// An update authored by `doc`, whose client id is its own.
    fn update_from(doc: &yrs::Doc, text: &str) -> Vec<u8> {
        let body = doc.get_or_insert_text("body");
        let before = doc.transact().state_vector();
        {
            let mut txn = doc.transact_mut();
            body.push(&mut txn, text);
        }
        doc.transact().encode_state_as_update_v1(&before)
    }

    #[test]
    fn resolves_the_user_whose_client_authored_the_update() {
        let doc = yrs::Doc::new();
        let update = update_from(&doc, "hello");
        register(&doc, "user-a", &[doc.client_id().get()]);

        assert_eq!(
            user_for_update(&doc.transact(), &update),
            Some("user-a".to_string())
        );
    }

    #[test]
    fn an_unregistered_client_resolves_to_none() {
        let doc = yrs::Doc::new();
        let update = update_from(&doc, "hello");
        register(&doc, "user-a", &[doc.client_id().get() + 1]);

        assert_eq!(user_for_update(&doc.transact(), &update), None);
    }

    #[test]
    fn a_doc_with_no_users_map_resolves_to_none() {
        let doc = yrs::Doc::new();
        let update = update_from(&doc, "hello");

        assert_eq!(user_for_update(&doc.transact(), &update), None);
    }

    #[test]
    fn an_update_merging_two_authors_reports_neither() {
        // A relayed update can carry blocks from several clients; naming one of
        // them as "the" editor would be a guess.
        let a = yrs::Doc::new();
        let b = yrs::Doc::with_client_id(a.client_id().get() + 100);
        let from_a = update_from(&a, "aaa");
        let from_b = update_from(&b, "bbb");

        let merged = yrs::Doc::new();
        {
            let mut txn = merged.transact_mut();
            txn.apply_update(Update::decode_v1(&from_a).unwrap())
                .unwrap();
            txn.apply_update(Update::decode_v1(&from_b).unwrap())
                .unwrap();
        }
        let combined = merged
            .transact()
            .encode_state_as_update_v1(&yrs::StateVector::default());

        register(&merged, "user-a", &[a.client_id().get()]);
        register(&merged, "user-b", &[b.client_id().get()]);

        assert_eq!(user_for_update(&merged.transact(), &combined), None);
    }

    /// The rendering contract both log lines rely on: a mapped id shows the
    /// name, an unmapped one shows `<none>`, and `user=` always carries the id
    /// so a mapping gap stays greppable rather than silent.
    #[test]
    fn name_falls_back_to_none_for_an_unmapped_id() {
        let names: std::collections::HashMap<String, String> =
            [("abc123".to_string(), "Ada Lovelace".to_string())]
                .into_iter()
                .collect();

        let rendered = |id: Option<&str>| {
            format!(
                "name={} user={}",
                id.and_then(|i| names.get(i))
                    .map(String::as_str)
                    .unwrap_or("<none>"),
                id.unwrap_or("-")
            )
        };

        assert_eq!(rendered(Some("abc123")), "name=Ada Lovelace user=abc123");
        assert_eq!(rendered(Some("nobody")), "name=<none> user=nobody");
        assert_eq!(rendered(None), "name=<none> user=-");
    }

    #[test]
    fn client_ids_identify_the_session_behind_an_update() {
        let a = yrs::Doc::new();
        let update = update_from(&a, "hello");

        assert_eq!(clients_for_update(&update), a.client_id().get().to_string());
        assert_eq!(clients_for_update(b"not an update"), "-");
    }

    /// A filemeta map insert is the production shape for a membership change.
    /// If the update names no client, clients_for_update reports "-" and
    /// user_for_update cannot attribute the change either.
    #[test]
    fn a_map_insert_update_still_names_its_client() {
        let doc = yrs::Doc::new();
        let map = doc.get_or_insert_map("filemeta_v0");
        let before = doc.transact().state_vector();
        {
            let mut txn = doc.transact_mut();
            map.insert(&mut txn, "notes/x.md", "guid-x");
        }
        let update = doc.transact().encode_state_as_update_v1(&before);

        assert_eq!(
            clients_for_update(&update),
            doc.client_id().get().to_string(),
            "a map insert must still name the client that made it"
        );
    }

    /// The shape that produced `clients=-` in production for months: a client
    /// that has already written to this doc emits its next update at a nonzero
    /// clock, which `Update::state_vector` omits entirely. Every test above
    /// writes a client's *first* update, the one case where the two APIs agree.
    #[test]
    fn a_clients_later_update_still_names_it() {
        let doc = yrs::Doc::new();
        let map = doc.get_or_insert_map("filemeta_v0");
        {
            let mut txn = doc.transact_mut();
            map.insert(&mut txn, "notes/first.md", "guid-1");
        }
        let before = doc.transact().state_vector();
        {
            let mut txn = doc.transact_mut();
            map.insert(&mut txn, "notes/second.md", "guid-2");
        }
        let update = doc.transact().encode_state_as_update_v1(&before);

        assert!(
            Update::decode_v1(&update)
                .unwrap()
                .state_vector()
                .is_empty(),
            "guards the reason for state_vector_lower: if this ever stops being \
             empty, upstream changed and the module doc needs revisiting"
        );
        assert_eq!(
            clients_for_update(&update),
            doc.client_id().get().to_string()
        );

        register(&doc, "user-a", &[doc.client_id().get()]);
        assert_eq!(
            user_for_update(&doc.transact(), &update),
            Some("user-a".to_string())
        );
    }

    /// A membership *removal*. Deleting a map entry creates no blocks, so this
    /// update is attributable only through its delete set - the shape that made
    /// every `removed=` line report `clients=-` while `added=` worked.
    #[test]
    fn a_map_removal_names_the_client_that_deleted() {
        let doc = yrs::Doc::new();
        let map = doc.get_or_insert_map("filemeta_v0");
        {
            let mut txn = doc.transact_mut();
            map.insert(&mut txn, "notes/x.md", "guid-x");
        }
        let before = doc.transact().state_vector();
        {
            let mut txn = doc.transact_mut();
            map.remove(&mut txn, "notes/x.md");
        }
        let update = doc.transact().encode_state_as_update_v1(&before);

        assert!(
            Update::decode_v1(&update)
                .unwrap()
                .state_vector_lower()
                .is_empty(),
            "a removal carries no blocks; if this changes, _clients_in can be simplified"
        );
        assert_eq!(
            clients_for_update(&update),
            doc.client_id().get().to_string()
        );

        register(&doc, "user-a", &[doc.client_id().get()]);
        assert_eq!(
            user_for_update(&doc.transact(), &update),
            Some("user-a".to_string())
        );
    }
}
