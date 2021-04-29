use crate::err::{Error, Result};
use async_net::UdpSocket;
use dnssector::{
    constants::{Class, Type, DNS_MAX_COMPRESSED_SIZE},
    DNSIterable, DNSSector, ParsedPacket, RdataIterable, DNS_FLAG_TC,
};
use std::{
    net::{IpAddr, SocketAddr},
    os::linux::raw,
};

const DNS_PORT: u16 = 53;
const SOURCE_ADDR: &str = "0.0.0.0:0";

pub struct Resolve {
    dns_server: SocketAddr,
}

impl Resolve {
    fn with_server<T: Into<IpAddr>>(ip: T) -> Self {
        let addr = SocketAddr::new(ip.into(), DNS_PORT);
        Self { dns_server: addr }
    }

    async fn query(&self, packet: ParsedPacket, name: &[u8]) -> Result<ParsedPacket> {
        let raw_packet = packet.into_packet();
        let raw_response = self.query_raw(&raw_packet).await?;
        let response = DNSSector::new(raw_response)
            .map_err(|e| Error::ParseResponse(query_string(name), e))?
            .parse()
            .map_err(|e| Error::ParseResponse(query_string(name), e))?;
        if response.flags() & DNS_FLAG_TC == DNS_FLAG_TC {
            return Err(Error::TcpUnsupported(
                query_string(name),
                self.dns_server.to_string(),
            ));
        }
        Ok(response)
    }

    async fn query_raw(&self, packet: &[u8]) -> Result<Vec<u8>> {
        let socket = UdpSocket::bind(SOURCE_ADDR).await.map_err(Error::Bind)?;
        socket
            .connect(self.dns_server)
            .await
            .map_err(|e| Error::Connect(self.dns_server.to_string(), e))?;
        // TODO: timeout
        socket
            .send(&packet)
            .await
            .map_err(|e| Error::Send(self.dns_server.to_string(), e))?;
        let mut response = vec![0; DNS_MAX_COMPRESSED_SIZE];
        let len = socket
            .recv(&mut response)
            .await
            .map_err(|e| Error::Recv(self.dns_server.to_string(), e))?;
        response.truncate(len);
        Ok(response)
    }

    async fn query_a(&self, name: &[u8]) -> Result<Vec<IpAddr>> {
        let query = dnssector::gen::query(name, Type::A, Class::IN)
            .map_err(|e| Error::DnsQuery(query_string(name), e))?;
        let response = self.query(query, name).await?;
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

fn query_string(query: &[u8]) -> String {
    String::from_utf8_lossy(query).to_string()
}
