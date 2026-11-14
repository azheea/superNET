//! superNET virtual network: devices with fixed addresses that reach each
//! other directly when they can (P2P), through another device when they
//! cannot, and through the coordinator as the last resort. Traffic between
//! devices is WireGuard end to end; relays only see ciphertext.

pub mod coord;
pub mod proto;

#[cfg(feature = "device")]
pub mod device;

#[cfg(all(test, feature = "device"))]
mod tests;
