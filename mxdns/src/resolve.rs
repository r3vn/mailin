use crate::err::{Error, Result};
use dnssector::{
    constants::{Class, Type},
    DNSIterable, ParsedPacket, RdataIterable,
};
use std::net::IpAddr;

pub struct Resolve {}

impl Resolve {
    fn query(&self, packet: ParsedPacket) -> Result<ParsedPacket> {
        todo!()
    }

    fn query_a(&self, name: &[u8]) -> Result<Vec<IpAddr>> {
        let query = dnssector::gen::query(name, Type::A, Class::IN)
            .map_err(|e| Error::DnsQuery("query A", format!("{}", e)))?;
        let response = self.query(query)?;
        let ips = extract_ips(response, name)?;
        todo!()
    }
}

// TODO: return an error
fn extract_ips(packet: ParsedPacket, query_name: &[u8]) -> Result<Vec<IpAddr>> {
    let mut ips = Vec::new();
    let mut response = packet.into_iter_answer();
    while let Some(i) = response {
        ips.push(i.rr_ip());
        response = i.next();
    }
    let (ips, errors): (Vec<_>, Vec<_>) = ips.into_iter().partition(std::result::Result::is_ok);
    if ips.is_empty() {
        if let Some(Err(e)) = errors.first() {
            let query = String::from_utf8_lossy(query_name).to_string();
            return Err(Error::ExtractIps(query, *e));
        }
    }
    let ips: Vec<_> = ips.into_iter().map(|r| r.unwrap()).collect();
    Ok(ips)
}
