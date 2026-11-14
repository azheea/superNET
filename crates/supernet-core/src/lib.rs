//! superNET core: rule-based routing between direct connections and
//! WireGuard nodes, exposed through a local HTTP + SOCKS5 proxy.

pub mod config;
pub mod dns;
pub mod engine;
pub mod geoip;
mod inbound;
pub mod outbound;
pub mod rules;
pub mod stats;
pub mod target;
pub mod tun;
pub mod wgconf;

pub use config::{Mode, Profile};
pub use engine::{Engine, NodeStatus, RouteInfo, Status};
pub use supernet_wg::{generate_private_key, public_key};
