//! Group lifecycle: create, add, remove, encrypt, decrypt (`plan.md` §4.2, §4.3).
//!
//! # What MLS buys us over a shared group key
//!
//! `plan.md` §4.2 rejects a single symmetric group key because removing a member
//! would require re-keying everyone *and* any member could decrypt all past
//! traffic. MLS fixes both: every Commit advances the epoch and derives fresh
//! secrets, so a removed member is locked out of subsequent epochs while
//! remaining members keep forward secrecy.
//!
//! The exit criterion in §7.1 Phase 4 is explicit — *"member removal advances the
//! epoch and the removed member cannot decrypt subsequent messages"* — and
//! [`Group::remove_member`] plus the `removed_member_cannot_decrypt` test are the
//! direct implementation of it.
//!
//! # Identity binding
//!
//! The MLS credential identity is the user's contact code (`plan.md` §2.2), not a
//! display name. Names are mutable and user-chosen; the contact code is derived
//! from the public keys. Binding the credential to the code means an MLS member
//! list is a list of cryptographic identities, which is what §4.3's "trust root"
//! discussion requires.

use crate::error::{MlsError, Result};
use crate::provider::MlsProvider;
use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;

/// The single ciphersuite this build speaks.
///
/// Pinned rather than negotiated: `plan.md` §11 calls for explicit versioning,
/// and a single ciphersuite means there is no downgrade surface. X25519 +
/// AES-128-GCM + SHA-256 + Ed25519 matches the identity keys in `anon-core`
/// (Ed25519 signing, X25519 agreement), so there is one set of primitives to
/// reason about.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// A member of a group, as seen from the local member's view.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GroupMember {
    /// Leaf index in the ratchet tree. Stable only within an epoch.
    pub index: u32,
    /// The member's contact code (MLS credential identity).
    pub identity: Vec<u8>,
    /// Whether this is the local member.
    pub is_self: bool,
}

/// A group's public description, safe to show in the UI.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GroupInfo {
    /// MLS group id.
    pub group_id: Vec<u8>,
    /// Current epoch. Increments on every Commit.
    pub epoch: u64,
    /// Members in the current epoch.
    pub members: Vec<GroupMember>,
}

/// An MLS group owned by the local member.
pub struct Group {
    inner: MlsGroup,
    signer: SignatureKeyPair,
}

impl Group {
    /// Create a new group with the local member as its only participant.
    ///
    /// `identity` is the creator's contact code. It becomes the MLS credential
    /// identity, so the group's trust root is cryptographic rather than a name.
    pub fn create(provider: &MlsProvider, identity: &[u8]) -> Result<Self> {
        let (credential, signer) = new_credential(provider, identity)?;
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();
        let inner = MlsGroup::new(provider, &signer, &config, credential)
            .map_err(|e| MlsError::Backend(format!("group creation failed: {e}")))?;
        Ok(Self { inner, signer })
    }

    /// Load a group from the provider's storage.
    ///
    /// Returns `Ok(None)` when the group is not present, which is the normal
    /// case for a group id that has never been joined.
    pub fn load(provider: &MlsProvider, group_id: &[u8]) -> Result<Option<Self>> {
        let gid = GroupId::from_slice(group_id);
        let inner = MlsGroup::load(provider.storage(), &gid)
            .map_err(|e| MlsError::Backend(format!("group load failed: {e}")))?;
        let Some(inner) = inner else {
            return Ok(None);
        };
        // The signature key is stored separately from group state (OpenMLS does
        // not manage it), so it must be read back by public key.
        let public = inner
            .own_leaf_node()
            .ok_or(MlsError::NotAMember)?
            .signature_key()
            .as_slice()
            .to_vec();
        let signer = SignatureKeyPair::read(
            provider.storage(),
            &public,
            CIPHERSUITE.signature_algorithm(),
        )
        .ok_or_else(|| MlsError::Backend("signature key missing from storage".into()))?;
        Ok(Some(Self { inner, signer }))
    }

    /// The group's id.
    pub fn group_id(&self) -> &[u8] {
        self.inner.group_id().as_slice()
    }

    /// The current epoch.
    pub fn epoch(&self) -> u64 {
        self.inner.epoch().as_u64()
    }

    /// The local member's leaf index.
    pub fn own_index(&self) -> u32 {
        self.inner.own_leaf_index().u32()
    }

    /// A public description of the group.
    pub fn info(&self) -> GroupInfo {
        let own = self.own_index();
        GroupInfo {
            group_id: self.group_id().to_vec(),
            epoch: self.epoch(),
            members: self
                .inner
                .members()
                .map(|m| GroupMember {
                    index: m.index.u32(),
                    identity: m.credential.serialized_content().to_vec(),
                    is_self: m.index.u32() == own,
                })
                .collect(),
        }
    }

    /// Produce a key package the local member can publish for others to add it.
    ///
    /// Key packages are single-use (`plan.md` §4.3: an invite must not grant
    /// history). The private material is written into the provider's storage, so
    /// the returned bytes are the *public* half only.
    pub fn key_package(provider: &MlsProvider, identity: &[u8]) -> Result<Vec<u8>> {
        let (credential, signer) = new_credential(provider, identity)?;
        let bundle = KeyPackage::builder()
            .build(CIPHERSUITE, provider, &signer, credential)
            .map_err(|e| MlsError::Backend(format!("key package build failed: {e}")))?;
        bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(|_| MlsError::Malformed("key package did not serialize"))
    }

    /// Add members from their serialized key packages.
    ///
    /// Returns the Commit and Welcome messages that must be delivered to the
    /// group and to the new members respectively. The local member's commit is
    /// merged immediately, so the local epoch advances as soon as this returns.
    pub fn add_members(
        &mut self,
        provider: &MlsProvider,
        key_packages: &[Vec<u8>],
    ) -> Result<AddOutcome> {
        if key_packages.is_empty() {
            return Err(MlsError::Malformed("no key packages supplied"));
        }
        let mut validated = Vec::with_capacity(key_packages.len());
        for bytes in key_packages {
            validated.push(validate_key_package(provider, bytes)?);
        }

        let (commit, welcome, _group_info) = self
            .inner
            .add_members(provider, &self.signer, &validated)
            .map_err(|e| MlsError::Backend(format!("add_members failed: {e}")))?;
        self.inner
            .merge_pending_commit(provider)
            .map_err(|e| MlsError::Backend(format!("merge after add failed: {e}")))?;

        Ok(AddOutcome {
            commit: serialize(&commit)?,
            welcome: serialize(&welcome)?,
            epoch: self.epoch(),
        })
    }

    /// Remove a member by leaf index.
    ///
    /// This is the operation `plan.md` §4.2 and §7.1 Phase 4 care about: it
    /// advances the epoch, and the removed member cannot decrypt anything sent
    /// afterwards. Refuses to remove the last member, which would leave a group
    /// nobody can read.
    pub fn remove_member(&mut self, provider: &MlsProvider, index: u32) -> Result<RemoveOutcome> {
        let leaf = LeafNodeIndex::new(index);
        if self.inner.member(leaf).is_none() {
            return Err(MlsError::UnknownMember(index));
        }
        if self.inner.members().count() <= 1 {
            return Err(MlsError::WouldEmptyGroup);
        }

        let (commit, _welcome, _group_info) = self
            .inner
            .remove_members(provider, &self.signer, &[leaf])
            .map_err(|e| MlsError::Backend(format!("remove_members failed: {e}")))?;
        self.inner
            .merge_pending_commit(provider)
            .map_err(|e| MlsError::Backend(format!("merge after remove failed: {e}")))?;

        Ok(RemoveOutcome {
            commit: serialize(&commit)?,
            epoch: self.epoch(),
        })
    }

    /// Encrypt an application message for the current epoch.
    ///
    /// The returned bytes are the MLS ciphertext. They are what goes into the
    /// padded frame from `anon-messaging` — MLS protects the content, the frame
    /// protects the metadata shape (`plan.md` §9.4).
    pub fn encrypt(&mut self, provider: &MlsProvider, plaintext: &[u8]) -> Result<Vec<u8>> {
        let out = self
            .inner
            .create_message(provider, &self.signer, plaintext)
            .map_err(|e| MlsError::Backend(format!("create_message failed: {e}")))?;
        serialize(&out)
    }

    /// Decrypt an application message.
    ///
    /// Returns [`MlsError::Decrypt`] for anything that is not a decryptable
    /// application message in the current epoch — including a message from a
    /// removed member's stale epoch, which is the property the removal test
    /// asserts.
    pub fn decrypt(&mut self, provider: &MlsProvider, message: &[u8]) -> Result<Vec<u8>> {
        let parsed = MlsMessageIn::tls_deserialize(&mut &message[..])
            .map_err(|_| MlsError::Malformed("message did not parse as MLS"))?;
        let protocol = parsed
            .try_into_protocol_message()
            .map_err(|_| MlsError::Malformed("message is not a protocol message"))?;
        let processed = self
            .inner
            .process_message(provider, protocol)
            .map_err(|_| MlsError::Decrypt)?;

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => Ok(app.into_bytes()),
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                // A Commit is how the epoch advances. Merging it is what makes a
                // removal take effect for the receiving side.
                self.inner
                    .merge_staged_commit(provider, *staged)
                    .map_err(|e| MlsError::Backend(format!("merge_staged_commit failed: {e}")))?;
                Err(MlsError::NotApplicationMessage)
            }
            _ => Err(MlsError::NotApplicationMessage),
        }
    }

    /// Join a group from a Welcome message.
    ///
    /// The ratchet tree is carried in the Welcome because the group is created
    /// with `use_ratchet_tree_extension(true)`, so no out-of-band tree transfer
    /// is needed — one less thing to get wrong over a peer-to-peer transport.
    pub fn join_from_welcome(provider: &MlsProvider, welcome: &[u8]) -> Result<Self> {
        let parsed = MlsMessageIn::tls_deserialize(&mut &welcome[..])
            .map_err(|_| MlsError::Malformed("welcome did not parse as MLS"))?;
        let body = match parsed.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(MlsError::InvalidWelcome("message is not a Welcome".into())),
        };
        let staged =
            StagedWelcome::new_from_welcome(provider, &MlsGroupJoinConfig::default(), body, None)
                .map_err(|e| MlsError::InvalidWelcome(format!("{e}")))?;
        let inner = staged
            .into_group(provider)
            .map_err(|e| MlsError::InvalidWelcome(format!("{e}")))?;

        let public = inner
            .own_leaf_node()
            .ok_or(MlsError::NotAMember)?
            .signature_key()
            .as_slice()
            .to_vec();
        let signer = SignatureKeyPair::read(
            provider.storage(),
            &public,
            CIPHERSUITE.signature_algorithm(),
        )
        .ok_or_else(|| MlsError::Backend("signature key missing after join".into()))?;
        Ok(Self { inner, signer })
    }

    /// Delete this group's state from storage.
    pub fn delete(&mut self, provider: &MlsProvider) -> Result<()> {
        self.inner
            .delete(provider.storage())
            .map_err(|e| MlsError::Backend(format!("group delete failed: {e}")))?;
        let _ = SignatureKeyPair::delete(
            provider.storage(),
            self.signer.public(),
            CIPHERSUITE.signature_algorithm(),
        );
        Ok(())
    }
}

impl std::fmt::Debug for Group {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let id: String = self.group_id().iter().map(|b| format!("{b:02x}")).collect();
        f.debug_struct("Group")
            .field("group_id", &id)
            .field("epoch", &self.epoch())
            .field("members", &self.inner.members().count())
            .finish()
    }
}

/// Result of adding members.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AddOutcome {
    /// Commit message for existing members.
    pub commit: Vec<u8>,
    /// Welcome message for the newly added members.
    pub welcome: Vec<u8>,
    /// The epoch after the add.
    pub epoch: u64,
}

/// Result of removing a member.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RemoveOutcome {
    /// Commit message for the remaining members.
    pub commit: Vec<u8>,
    /// The epoch after the removal.
    pub epoch: u64,
}

/// Build a credential bound to `identity` and store its signature key.
fn new_credential(
    provider: &MlsProvider,
    identity: &[u8],
) -> Result<(CredentialWithKey, SignatureKeyPair)> {
    if identity.is_empty() {
        return Err(MlsError::InvalidIdentity("identity must not be empty"));
    }
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
        .map_err(|e| MlsError::Backend(format!("signature key generation failed: {e}")))?;
    signer
        .store(provider.storage())
        .map_err(|e| MlsError::Backend(format!("signature key store failed: {e}")))?;

    let credential = BasicCredential::new(identity.to_vec());
    Ok((
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        },
        signer,
    ))
}

/// Parse and verify a serialized key package.
///
/// Verification matters: an unverified key package is attacker-supplied bytes
/// that would otherwise be added to the ratchet tree.
fn validate_key_package(provider: &MlsProvider, bytes: &[u8]) -> Result<KeyPackage> {
    let unverified = KeyPackageIn::tls_deserialize(&mut &bytes[..])
        .map_err(|_| MlsError::InvalidKeyPackage("did not parse".into()))?;
    unverified
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| MlsError::InvalidKeyPackage(format!("{e}")))
}

fn serialize<T: TlsSerialize>(value: &T) -> Result<Vec<u8>> {
    value
        .tls_serialize_detached()
        .map_err(|_| MlsError::Malformed("MLS message did not serialize"))
}
