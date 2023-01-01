/**
 * Lib.rs centrally exports all the modules for the package
 */

// Backend Logic for network sniffing
mod net_logic;
pub use crate::net_logic::sniffer;

// Frontend Integration using a Façade pattern
mod facade;
pub use crate::facade::frontend_api;