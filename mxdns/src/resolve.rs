use crate::err::{Error, Result};
use dnssector::{
    constants::{Class, Type},
    DNSIterable, ParsedPacket, RdataIterable,
};
use std::net::{IpAddr, Ipv4Addr};

pub struct Resolve {}

impl Resolve {
    fn query(&self, packet: ParsedPacket) -> Result<ParsedPacket> {
        todo!()
    }

    fn query_a(&self, name: &[u8]) -> Result<Vec<IpAddr>> {
        let query = dnssector::gen::query(name, Type::A, Class::IN)
            .map_err(|e| Error::DnsQuery("query A", format!("{}", e)))?;
        let response = self.query(query)?;
        let ips = extract_ips(response);
        todo!()
    }
}

// TODO: return an error
fn extract_ips(packet: ParsedPacket, query_name: &'static str) -> Result<Vec<IpAddr>> {
    let mut ips = Vec::new();
    let mut response = packet.into_iter_answer();
    while let Some(i) = response {
        if let Ok(addr) = i.rr_ip() {
            ips.push(addr);
        }
        response = i.next();
    }
    Ok(ips)
}
