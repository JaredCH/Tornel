//! The IPC boundary guard (`plan.md` §7.3).
//!
//! §7.3 states the rule plainly: *"no private key, seed, or DB handle ever
//! crosses this boundary"*. A comment cannot enforce that, so this test reads the
//! DTO source and fails if a field appears that the inventory does not know
//! about, or whose name looks like secret material.
//!
//! # Why read the source instead of reflecting over the types
//!
//! Rust has no runtime reflection, and a `macro_rules!` inventory would only
//! cover fields someone remembered to route through the macro. Parsing the
//! declared `pub` fields catches the case that actually matters: a developer adds
//! a field to a DTO and does not think about the boundary. That is exactly the
//! mistake this test exists to catch.

use anon_ipc::{dto_inventory, FORBIDDEN_FIELD_MARKERS};

/// Every `pub <name>: <type>` field declared in `src/dto.rs`.
///
/// Deliberately a simple line scan rather than a real parser: the DTO file is
/// plain struct definitions, and a scan that is easy to read is easier to trust
/// than a parser that might silently skip something.
fn declared_dto_fields() -> Vec<String> {
    let src = include_str!("../src/dto.rs");
    let mut fields = Vec::new();

    for line in src.lines() {
        let trimmed = line.trim();

        // Skip comments and attributes.
        if trimmed.starts_with("//") || trimmed.starts_with("#[") || trimmed.starts_with("///") {
            continue;
        }

        // Match `pub name: Type,` — the shape every DTO field takes.
        let Some(rest) = trimmed.strip_prefix("pub ") else {
            continue;
        };
        let Some((name, _ty)) = rest.split_once(':') else {
            continue;
        };

        let name = name.trim();
        // Reject anything that is not a plain identifier, so `pub fn` and
        // `pub struct` are not mistaken for fields.
        if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            continue;
        }
        fields.push(name.to_string());
    }

    fields
}

#[test]
fn every_declared_dto_field_is_in_the_inventory() {
    // The inventory is the reviewed list of what may cross the boundary. A field
    // missing from it means a value crossed without review.
    let inventory = dto_inventory();
    let declared = declared_dto_fields();

    assert!(
        !declared.is_empty(),
        "the DTO scan found no fields; the parser or the file layout changed"
    );

    let mut unreviewed: Vec<&String> = declared
        .iter()
        .filter(|f| !inventory.contains(&f.as_str()))
        .collect();
    unreviewed.sort();
    unreviewed.dedup();

    assert!(
        unreviewed.is_empty(),
        "these DTO fields are not in dto_inventory() and so have not been reviewed \
         for the §7.3 boundary rule: {unreviewed:?}"
    );
}

#[test]
fn no_dto_field_name_looks_like_secret_material() {
    // Belt and braces: even a reviewed field must not be *named* like a secret,
    // because that is a strong signal it carries one.
    for field in declared_dto_fields() {
        let lower = field.to_ascii_lowercase();
        for marker in FORBIDDEN_FIELD_MARKERS {
            assert!(
                !lower.contains(marker),
                "DTO field `{field}` contains the forbidden marker `{marker}`; \
                 secret material must not cross the §7.3 boundary"
            );
        }
    }
}

#[test]
fn the_inventory_and_the_dtos_describe_the_same_set_of_names() {
    // The inventory is a flat list of reviewed *names*, so the same name appearing
    // in two structs (`contact_code` in both `IdentityView` and `PeerView`,
    // `expires_at` in four) is expected and correct. What must hold is that the
    // two sides describe the same set — no unreviewed field, no stale entry.
    //
    // This is the conjunction of the two directional tests above, stated once so a
    // failure here points at "the sets differ" rather than at one direction.
    let mut inventory: Vec<String> = dto_inventory().iter().map(|s| s.to_string()).collect();
    let mut declared = declared_dto_fields();
    inventory.sort();
    inventory.dedup();
    declared.sort();
    declared.dedup();

    assert_eq!(
        inventory, declared,
        "the reviewed inventory and the declared DTO fields must name the same set"
    );
}

#[test]
fn the_inventory_does_not_list_fields_that_no_longer_exist() {
    // The reverse drift: a stale inventory entry means the reviewed list no
    // longer describes the code, so a future reader cannot trust it.
    let declared = declared_dto_fields();
    let inventory = dto_inventory();

    let mut stale: Vec<&&str> = inventory
        .iter()
        .filter(|f| !declared.iter().any(|d| d == *f))
        .collect();
    stale.sort();
    stale.dedup();

    assert!(
        stale.is_empty(),
        "dto_inventory() lists fields that are not declared in dto.rs: {stale:?}"
    );
}

#[test]
fn the_forbidden_marker_list_covers_the_obvious_cases() {
    // If someone trims this list, the guard above silently weakens.
    for required in ["secret", "private", "seed", "passphrase", "password"] {
        assert!(
            FORBIDDEN_FIELD_MARKERS.contains(&required),
            "the forbidden-marker list must include `{required}`"
        );
    }
}

#[test]
fn a_secret_handle_does_not_reveal_its_value() {
    // §7.3 mechanism 2: the webview may hold a handle but cannot derive the
    // secret. The handle is random per mint, and its display form is the handle
    // itself (which is not the secret).
    use anon_ipc::SecretHandle;

    let a = SecretHandle::mint();
    let b = SecretHandle::mint();
    assert_ne!(a, b, "handles must not be predictable across mints");
    assert_eq!(a.as_str().len(), 32, "a handle is 16 random bytes as hex");
    assert_eq!(a.label().len(), 8, "the display label is a short prefix");
    assert!(
        a.as_str().starts_with(a.label()),
        "the label must be a prefix of the handle, not a different value"
    );
}
