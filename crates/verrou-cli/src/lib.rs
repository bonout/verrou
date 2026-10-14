//! Le terminal de Verrou : la liaison avec l'app (`verrou link`), le
//! dialogue par son pont, l'agent SSH, et la signature des commits git par
//! cet agent.
//!
//! Le coffre n'est déchiffré que dans l'app (Touch ID, mot de passe
//! principal) : la CLI lui demande ce qu'elle affiche, et l'app décide de ce
//! qu'elle donne (voir `verrou_bridge::access`).

pub mod agent;
pub mod config;
pub mod git_signing;
pub mod remote;
