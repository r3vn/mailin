use crate::err::{Error, Result};
use dnssector::{
    constants::{Class, Type},
    DNSIterable, ParsedPacket, RdataIterable,
};
use std::net::{IpAddr, SocketAddr};

const DNS_PORT: u16 = 53;

pub struct Resolve {
    dns_server: SocketAddr,
}

impl Resolve {
    fn with_server<T: Into<IpAddr>>(ip: T) -> Self {
        let addr = SocketAddr::new(ip.into(), DNS_PORT);
        Self { dns_server: addr }
    }

    fn query(&self, packet: ParsedPacket) -> Result<ParsedPacket> {
        let raw_packet = packet.into_packet();
        todo!()
    }

    fn query_a(&self, name: &[u8]) -> Result<Vec<IpAddr>> {
        let query = dnssector::gen::query(name, Type::A, Class::IN)
            .map_err(|e| Error::DnsQuery(String::from_utf8_lossy(name).to_string(), e))?;
        let response = self.query(query)?;
        extract_ips(response, name)
    }
}

fn extract_ips(mut packet: ParsedPacket, query_name: &[u8]) -> Result<Vec<IpAddr>> {
    use std::result::Result as StdResult;

    let mut ips = Vec::new();
    let mut response = packet.into_iter_answer();
    while let Some(i) = response {
        ips.push(i.rr_ip());
        response = i.next();
    }
    let (ips, errors): (Vec<_>, Vec<_>) = ips.into_iter().partition(StdResult::is_ok);
    if ips.is_empty() {
        if let Some(Err(e)) = errors.into_iter().nth(0) {
            let query = String::from_utf8_lossy(query_name).to_string();
            return Err(Error::ExtractIps(query, e));
        }
    }
    let ips: Vec<_> = ips.into_iter().map(StdResult::unwrap).collect();
    Ok(ips)
}
