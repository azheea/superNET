//! Country lookups for GEOIP rules, from a MaxMind-format database.

use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};

pub struct GeoIp {
    reader: maxminddb::Reader<Vec<u8>>,
}

impl GeoIp {
    pub fn open(path: &Path) -> Result<GeoIp> {
        let reader = maxminddb::Reader::open_readfile(path).with_context(|| format!("打开 GeoIP 数据库 {}", path.display()))?;
        Ok(GeoIp { reader })
    }

    /// ISO country code, e.g. `CN`.
    pub fn country(&self, ip: IpAddr) -> Option<String> {
        let result = self.reader.lookup(ip).ok()?;
        let country: maxminddb::geoip2::Country = result.decode().ok()??;
        country.country.iso_code.or(country.registered_country.iso_code).map(str::to_string)
    }
}
