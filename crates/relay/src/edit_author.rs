//! Identify the Yjs client ids behind an update.
//!
//! Two traps in reading those client ids, both of which fail by reporting no
//! author rather than a wrong one:
//!
//! 1. Use `Update::state_vector_lower`, never `state_vector`. The latter is an
//!    upper bound over blocks contiguous from clock 0, so it drops any client
//!    whose first block in the update has a nonzero clock - which is every
//!    update after a client's first.
//! 2. Insertions and deletions live in different places. A deletion creates no
//!    blocks, so a delete-only update has an empty state vector by any measure
//!    and is attributable only through `delete_set`.

use std::collections::HashSet;
use yrs::updates::decoder::Decode;
use yrs::Update;

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

/// The yjs client ids an update came from, ascending.
pub fn clients_in_update(update: &[u8]) -> Vec<u64> {
    let Ok(decoded) = Update::decode_v1(update) else {
        return Vec::new();
    };

    let mut ids: Vec<u64> = _clients_in(&decoded).into_iter().collect();
    ids.sort_unstable();
    ids
}

/// True when every client in the update is server-authored (53-bit yrs id,
/// >= 2^32). PUD registration writes are the main case: the server mutates
/// the doc's `users` map under its own client id, which fires
/// `observe_update_v1` and would otherwise produce a webhook for internal
/// bookkeeping that no human produced.
pub fn is_server_only_update(update: &[u8]) -> bool {
    let Ok(decoded) = Update::decode_v1(update) else {
        return false;
    };

    let ids = _clients_in(&decoded);
    !ids.is_empty() && ids.iter().all(|id| *id >= (1u64 << 32))
}

#[cfg(test)]
mod tests {
    use super::*;
    use yrs::{Map, ReadTxn, Text, Transact};

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
    fn clients_in_update_names_the_author() {
        let a = yrs::Doc::new();
        let update = update_from(&a, "hello");

        assert_eq!(clients_in_update(&update), vec![a.client_id().get()]);
        assert_eq!(clients_in_update(b"not an update"), Vec::<u64>::new());
    }

    #[test]
    fn a_map_insert_still_names_its_client() {
        let doc = yrs::Doc::new();
        let map = doc.get_or_insert_map("filemeta_v0");
        let before = doc.transact().state_vector();
        {
            let mut txn = doc.transact_mut();
            map.insert(&mut txn, "notes/x.md", "guid-x");
        }
        let update = doc.transact().encode_state_as_update_v1(&before);

        assert_eq!(clients_in_update(&update), vec![doc.client_id().get()]);
    }

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

        assert_eq!(clients_in_update(&update), vec![doc.client_id().get()]);
    }

    #[test]
    fn a_later_update_still_names_its_client() {
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
            "guards the reason for state_vector_lower"
        );
        assert_eq!(clients_in_update(&update), vec![doc.client_id().get()]);
    }

    #[test]
    fn is_server_only_detects_53_bit_ids() {
        let server_doc = yrs::Doc::with_client_id((1u64 << 32) + 42);
        let update = update_from(&server_doc, "pud write");
        assert!(is_server_only_update(&update));

        let user_doc = yrs::Doc::with_client_id(42);
        let user_update = update_from(&user_doc, "human edit");
        assert!(!is_server_only_update(&user_update));
    }

    #[test]
    fn mixed_server_and_user_ids_is_not_server_only() {
        let user = yrs::Doc::with_client_id(42);
        let server = yrs::Doc::with_client_id((1u64 << 32) + 1);
        let from_user = update_from(&user, "user");
        let from_server = update_from(&server, "server");

        let merged = yrs::Doc::new();
        {
            let mut txn = merged.transact_mut();
            txn.apply_update(Update::decode_v1(&from_user).unwrap())
                .unwrap();
            txn.apply_update(Update::decode_v1(&from_server).unwrap())
                .unwrap();
        }
        let combined = merged
            .transact()
            .encode_state_as_update_v1(&yrs::StateVector::default());

        assert!(!is_server_only_update(&combined));
    }
}
