//! Peer messaging: wire format, framing, and delivery (`plan.md` §9).
//!
//! This crate sits above [`anon_transport`] and [`anon_storage`]:
//!
//! * it never touches a socket — delivery goes through the
//!   `AnonymityTransport` trait, which enforces the no-clearnet gate (`§3.4`);
//! * it never touches SQL directly — persistence goes through `Store`, so the
//!   retention and crypto-shredding rules apply automatically (`§6`).
//!
//! # Scope
//!
//! This implements the **wire format, padding, and delivery mechanics** of §9.1
//! and §9.2. The *ratchet* itself is deliberately not hand-rolled: `plan.md` §4.2
//! requires a vetted protocol (MLS via `openmls`, or a Double Ratchet) for key
//! management. What lives here is the framing those protocols ride in, plus the
//! replay/ordering logic that Tor's lack of ordering guarantees makes necessary.
//!
//! Keeping framing separate from the ratchet is what lets the group protocol be
//! swapped (`§3.4`) without redesigning the wire format.

pub mod deliver;
pub mod error;
pub mod frame;
pub mod group;
pub mod mailbox_host;
pub mod service;

pub use deliver::{DeliveryOutcome, DeliveryReport, Outbox};
pub use error::{FrameError, MessageError, Result};
pub use frame::{Frame, MessageId};
pub use group::GroupMessaging;
pub use mailbox_host::{refusal_to_error, MailboxHost};
pub use service::MessagingService;

/// Protocol version carried in every frame (`plan.md` §11, "versioning").
///
/// Embedded so a future change is negotiable rather than breaking.
pub const PROTOCOL_VERSION: u8 = 1;

/// Size buckets for padding (`plan.md` §9.4, baseline mitigation).
///
/// Every frame is padded up to one of these sizes so an observer cannot
/// distinguish a short message from a long one by length alone. The buckets are
/// powers of four-ish so a message grows by at most ~4x, bounding overhead.
/// Extended up to 512 KiB to support padded image and file attachments over Tor.
pub const PAD_BUCKETS: &[usize] = &[512, 2048, 8192, 32_768, 131_072, 524_288];

/// Size of the AEAD authentication tag appended to each frame.
pub const TAG_LEN: usize = 16;

/// Nonce length for the frame AEAD.
pub const NONCE_LEN: usize = 12;
