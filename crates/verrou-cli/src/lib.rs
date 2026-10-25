//! Verrou's terminal: the link with the app (`verrou link`), the dialogue
//! through its bridge, the SSH agent, git commit signing through that
//! agent, and secrets handed to a command (`verrou run`) or written into a
//! template (`verrou inject`).
//!
//! The vault is only decrypted in the app (Touch ID, master password): the
//! CLI asks it for what it displays, and the app decides what it gives (see
//! `verrou_bridge::access`).

pub mod agent;
pub mod config;
pub mod git_signing;
pub mod inject;
pub mod items;
pub mod remote;
pub mod run;
