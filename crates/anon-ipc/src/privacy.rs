use super::*;
use anon_transport::DiscoveryKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivacyConfig {
    restricted: bool,
    shaping: bool,
    peers: BTreeMap<String, InvitePayload>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InvitePayload {
    version: u8,
    contact_code: String,
    onion: String,
    discovery: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedInvite {
    payload: InvitePayload,
    signature: String,
}

fn privacy_error(message: &str) -> CommandError {
    CommandError::new("privacy", message)
}

fn transcript(payload: &InvitePayload) -> std::result::Result<Vec<u8>, CommandError> {
    let mut bytes = b"anon/signed-invite/v1\0".to_vec();
    bytes.extend(serde_json::to_vec(payload).map_err(|_| privacy_error("invalid invitation"))?);
    Ok(bytes)
}

impl Backend {
    fn read_privacy(&self) -> std::result::Result<PrivacyConfig, CommandError> {
        self.store
            .privacy_config()
            .map_err(CommandError::from)?
            .map(|value| {
                serde_json::from_str(&value)
                    .map_err(|_| privacy_error("invalid saved privacy configuration"))
            })
            .transpose()
            .map(|value| value.unwrap_or_default())
    }

    fn apply_privacy(&self, config: &PrivacyConfig) -> std::result::Result<(), CommandError> {
        if self.messaging.transport().anonymity() == AnonymityClass::None {
            return Ok(());
        }
        let key = DiscoveryKey::for_identity(&self.identity);
        let mut authorized = vec![key.public_key()];
        authorized.extend(config.peers.values().map(|peer| peer.discovery.clone()));
        self.messaging
            .transport()
            .configure_discovery(&key, config.restricted.then_some(authorized.as_slice()))
            .map_err(|_| {
                privacy_error("could not apply discovery protection; sending remains unavailable")
            })?;
        let peers = config
            .peers
            .values()
            .map(|peer| OnionId::parse(&peer.onion))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| privacy_error("invalid saved peer route"))?;
        self.messaging
            .transport()
            .configure_shaping(&peers, config.shaping)
            .map_err(|_| {
                privacy_error("could not apply traffic shaping; sending remains unavailable")
            })
    }

    fn persist_privacy(&self, config: &PrivacyConfig) -> std::result::Result<(), CommandError> {
        let value = serde_json::to_string(config)
            .map_err(|_| privacy_error("invalid privacy configuration"))?;
        self.store
            .set_privacy_config(&value)
            .map_err(CommandError::from)
    }

    pub fn initialize_privacy(&self, fresh_profile: bool) -> std::result::Result<(), CommandError> {
        let _guard = self.privacy_lock.lock().unwrap();
        let mut config = self.read_privacy()?;
        if self
            .store
            .privacy_config()
            .map_err(CommandError::from)?
            .is_none()
        {
            config.restricted = fresh_profile;
            self.persist_privacy(&config)?;
        }
        self.apply_privacy(&config)
    }

    pub fn privacy_view(&self) -> std::result::Result<crate::PrivacyView, CommandError> {
        let config = self.read_privacy()?;
        let legacy_contacts = self
            .store
            .contacts()
            .map_err(CommandError::from)?
            .iter()
            .filter(|contact| !config.peers.contains_key(&contact.contact_code))
            .count();
        Ok(crate::PrivacyView {
            restricted_discovery: config.restricted,
            legacy_contacts,
            traffic_shaping: config.shaping,
        })
    }

    pub fn enable_restricted_discovery(
        &self,
    ) -> std::result::Result<crate::PrivacyView, CommandError> {
        let _guard = self.privacy_lock.lock().unwrap();
        if self.privacy_view()?.legacy_contacts != 0 {
            return Err(privacy_error("exchange signed invitations with every saved contact before enabling restricted discovery"));
        }
        let mut config = self.read_privacy()?;
        config.restricted = true;
        self.persist_privacy(&config)?;
        if let Err(error) = self.apply_privacy(&config) {
            self.messaging.transport().shutdown();
            return Err(error);
        }
        self.privacy_view()
    }

    pub fn export_invite(&self) -> std::result::Result<String, CommandError> {
        let onion = self
            .messaging
            .transport()
            .local_onion()
            .ok_or_else(|| privacy_error("Tor is still starting"))?;
        let payload = InvitePayload {
            version: 1,
            contact_code: self.contact_code().map_err(CommandError::from)?,
            onion: onion.as_str().into(),
            discovery: DiscoveryKey::for_identity(&self.identity).public_key(),
        };
        let signature = hex_encode(&self.identity.sign(&transcript(&payload)?).to_bytes());
        Ok(format!(
            "tornel1:{}",
            serde_json::to_string(&SignedInvite { payload, signature })
                .map_err(|_| privacy_error("could not encode invitation"))?
        ))
    }

    pub fn set_traffic_shaping(
        &self,
        enabled: bool,
    ) -> std::result::Result<crate::PrivacyView, CommandError> {
        let _guard = self.privacy_lock.lock().unwrap();
        let mut config = self.read_privacy()?;
        if enabled
            && (!config.restricted
                || self.privacy_view()?.legacy_contacts != 0
                || config.peers.len() > 4)
        {
            return Err(privacy_error("traffic shaping requires restricted discovery and at most four signed-invite contacts"));
        }
        config.shaping = enabled;
        self.persist_privacy(&config)?;
        if let Err(error) = self.apply_privacy(&config) {
            self.messaging.transport().shutdown();
            return Err(error);
        }
        self.privacy_view()
    }

    pub fn add_peer(
        &self,
        contact_code: &str,
        label: Option<String>,
    ) -> std::result::Result<(PeerView, String), CommandError> {
        let _guard = self.privacy_lock.lock().unwrap();
        let Some(encoded) = contact_code.trim().strip_prefix("tornel1:") else {
            if self.read_privacy()?.restricted {
                return Err(privacy_error(
                    "this persona requires a signed invitation with a discovery key",
                ));
            }
            return self.save_peer(contact_code, label);
        };
        if encoded.len() > 4096 {
            return Err(privacy_error("invitation is too large"));
        }
        let invite: SignedInvite = serde_json::from_str(encoded)
            .map_err(|_| privacy_error("invalid signed invitation"))?;
        if invite.payload.version != 1
            || !DiscoveryKey::validate_public_key(&invite.payload.discovery)
        {
            return Err(privacy_error(
                "unsupported invitation or invalid discovery key",
            ));
        }
        OnionId::parse(&invite.payload.onion)
            .map_err(|_| privacy_error("invalid invitation onion address"))?;
        let code = ContactCode::decode(&invite.payload.contact_code)
            .map_err(|_| privacy_error("invalid invitation contact code"))?;
        let signature: [u8; 64] = hex::decode(&invite.signature)
            .map_err(|_| privacy_error("invalid invitation signature"))?
            .try_into()
            .map_err(|_| privacy_error("invalid invitation signature"))?;
        code.public_identity()
            .verify(&transcript(&invite.payload)?, &signature)
            .map_err(|_| privacy_error("invitation signature verification failed"))?;
        let mut config = self.read_privacy()?;
        let canonical = code.to_code().map_err(CommandError::from)?;
        if config.peers.len() >= 159 && !config.peers.contains_key(&canonical) {
            return Err(privacy_error(
                "this persona has reached its discovery contact limit",
            ));
        }
        if config.shaping && config.peers.len() >= 4 && !config.peers.contains_key(&canonical) {
            return Err(privacy_error(
                "disable traffic shaping before adding more than four contacts",
            ));
        }
        let label = label.unwrap_or_default();
        if label.contains('|') {
            return Err(privacy_error("invalid peer label"));
        }
        let saved = self.save_peer(
            &canonical,
            Some(format!("{}|{}", label.trim(), invite.payload.onion)),
        )?;
        config.peers.insert(canonical, invite.payload);
        self.persist_privacy(&config)?;
        if let Err(error) = self.apply_privacy(&config) {
            self.messaging.transport().shutdown();
            return Err(error);
        }
        Ok(saved)
    }
}
