/*
//! DNS utilities for email servers.
//!
//! Currently, DNS based blocklists and reverse DNS lookups are supported.
//! The crate also supports forward confirmed reverse dns checks.
//!
//! Because blocklists are IP4 based, these utilities only support IP4
//! addresses. IP6 addresses are converted to IP4 when possible.
//!
//! # Examples
//! ```no_run
//! use mxdns::{MxDns, FCrDNS};
//!
//! let blocklists = vec!["zen.spamhaus.org.","dnsbl-1.uceprotect.net."];
//! let mxdns = MxDns::new(blocklists).unwrap();
//!
//! // Check if an IP Address is present on blocklists
//! let is_blocked = mxdns.is_blocked([127, 0, 0, 2]).unwrap();
//! assert!(is_blocked);
//!
//! // Reverse lookup a DNS address
//! let rdns = mxdns.reverse_dns([193, 25, 101, 5]).unwrap().unwrap();
//! assert_eq!(rdns, "mail.alienscience.org.");
//!
//! // Check that the ip resolved from the name obtained by the reverse dns matches the ip
//! if let Ok(FCrDNS::Confirmed(_domain)) = mxdns.fcrdns([193, 25, 101, 5]) {
//!    // _domain is Confirmed
//! }
//! ```

#![forbid(unsafe_code)]
#![forbid(missing_docs)]
*/
mod blocklist;
mod err;
mod join_all;
mod resolve;

pub use crate::{
    blocklist::BlockList,
    err::{Error, Result},
    join_all::join_all,
    resolve::Resolve,
};
use log::Level::Debug;
use log::{debug, log_enabled};
use resolv_conf;
use resolve::DEFAULT_TIMEOUT;
use smol::future::{self, FutureExt};
use std::{
    fs::File,
    io::Read,
    matches,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

const RESOLV_CONF: &str = "/etc/resolv.conf";

/// Utilities for looking up IP addresses on blocklists and doing reverse DNS
#[derive(Clone)]
pub struct MxDns {
    bootstrap: Resolve,
    blocklists: Vec<String>,
}

/// The result of a FCrDNS lookup
#[derive(Debug)]
pub enum FCrDNS {
    /// Reverse lookup failed
    NoReverse,
    /// Reverse lookup was successful but could not be forward confirmed
    UnConfirmed(String),
    /// The reverse lookup was forward confirmed
    Confirmed(String),
}

impl FCrDNS {
    /// Is the result a confirmed reverse dns value?
    pub fn is_confirmed(&self) -> bool {
        matches!(self, Self::Confirmed(_))
    }
}

impl MxDns {
    /// Create a MxDns using the system provided nameserver config
    pub fn new<S>(blocklists_fqdn: S) -> Result<Self>
    where
        S: IntoIterator,
        S::Item: Into<String>,
    {
        let mut buf = Vec::with_capacity(256);
        let mut file = File::open(RESOLV_CONF)
            .map_err(|e| Error::ResolvConfRead(RESOLV_CONF.to_string(), e))?;
        file.read_to_end(&mut buf)
            .map_err(|e| Error::ResolvConfRead(RESOLV_CONF.to_string(), e))?;
        let conf = resolv_conf::Config::parse(&buf)
            .map_err(|e| Error::ResolvConfParse(RESOLV_CONF.to_string(), e))?;
        let nameservers = conf.get_nameservers_or_local();
        if let Some(ip) = nameservers.first() {
            let ip_addr: IpAddr = ip.into();
            Ok(Self::with_dns(ip_addr, blocklists_fqdn))
        } else {
            Err(Error::NoNameservers(RESOLV_CONF.to_string()))
        }
    }

    /// Create a MxDns that uses the given DNS server for standard queries.
    pub fn with_dns<I, S>(bootstrap_dns: I, blocklists_fqdn: S) -> Self
    where
        I: Into<IpAddr>,
        S: IntoIterator,
        S::Item: Into<String>,
    {
        let ip = bootstrap_dns.into();
        let bootstrap = Resolve::new(ip, DEFAULT_TIMEOUT);
        let blocklists: Vec<String> = blocklists_fqdn.into_iter().map(|i| i.into()).collect();
        Self {
            bootstrap,
            blocklists,
        }
    }

    /// Queries blocklists for the given address
    /// Returns a vector where each entry indicates if the address is on the blocklist
    pub fn on_blocklists<A>(&self, addr: A) -> Vec<Result<bool>>
    where
        A: Into<IpAddr>,
    {
        if self.blocklists.is_empty() {
            return vec![];
        }
        let ip: IpAddr = addr.into();

        let ret = smol::block_on(async {
            let mut all_checks = Vec::new();
            for blocklist in &self.blocklists {
                let one_check = self.check_blocklist(blocklist, ip);
                all_checks.push(one_check.boxed());
            }
            join_all(all_checks).await
        });
        if log_enabled!(Debug) {
            for i in ret.iter().enumerate() {
                debug!("{} is blocked by {} = {:?}", ip, self.blocklists[i.0], i.1);
            }
        }
        ret
    }

    async fn check_blocklist(&self, blocklist: &str, ip: IpAddr) -> Result<bool> {
        let resolver = BlockList::lookup_ns(blocklist, &self.bootstrap).await?;
        let blocklist_lookup = BlockList::new(resolver, blocklist);
        blocklist_lookup.is_blocked(ip).await
    }

    /// Returns true if the address is on any of the blocklists
    pub fn is_blocked<A>(&self, addr: A) -> Result<bool>
    where
        A: Into<IpAddr>,
    {
        let mut res = self.on_blocklists(addr);
        if res.is_empty() {
            Ok(false)
        } else if res.iter().all(|r| r.is_err()) {
            res.pop().unwrap_or_else(|| Ok(false))
        } else {
            Ok(res.into_iter().any(|r| r.unwrap_or(false)))
        }
    }

    /*
    /// Does a reverse DNS lookup on the given ip address
    /// Returns Ok(None) if no reverse DNS entry exists.
    pub fn reverse_dns<A>(&self, ip: A) -> Result<Option<String>>
    where
        A: Into<IpAddr>,
    {
        self.bootstrap.query_ptr(ip.into())
        let ip = ip.into();
        let ip = to_ipv4(ip)?;
        let query = format_ipv4(ip, "in-addr.arpa");
        let mut runtime = Runtime::new().unwrap();
        let (task, mut client) = connect_client(self.bootstrap);
        runtime.spawn(task);
        let rdns = lookup_ptr(&mut client, &query);
        runtime.block_on(rdns).map(|o| o.map(|name| name.to_utf8()))
    }

    /// Does a Forward Confirmed Reverse DNS check on the given ip address
    /// This checks that the reverse lookup on the ip address gives a domain
    /// name that will resolve to the original ip address.
    /// Returns the confirmed reverse DNS domain name.
    pub fn fcrdns<A>(&self, ip: A) -> Result<FCrDNS>
    where
        A: Into<IpAddr>,
    {
        let ipaddr = ip.into();
        let ipaddr = to_ipv4(ipaddr)?;
        let fqdn = match self.reverse_dns(ipaddr)? {
            None => return Ok(FCrDNS::NoReverse),
            Some(s) => s,
        };
        debug!("reverse lookup for {} = {}", ipaddr, fqdn);
        let (task, client) = connect_client(self.bootstrap);
        let mut runtime = Runtime::new().unwrap();
        runtime.spawn(task);
        let forward = lookup_ip(client, &fqdn);
        let is_confirmed = runtime.block_on(forward).map(|maybe_ip| {
            maybe_ip
                .filter(|c| {
                    debug!("ipaddr = {}, forward confirmed = {} ", ipaddr, c);
                    c == &ipaddr
                })
                .is_some()
        });
        match is_confirmed {
            Ok(true) => Ok(FCrDNS::Confirmed(fqdn)),
            Ok(false) => Ok(FCrDNS::UnConfirmed(fqdn)),
            Err(e) => Err(e),
        }
    }
    */
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocklists() -> Vec<(&'static str, bool)> {
        // Tuples are (fqdn, has_nameserver)
        // Removed:  ("dnsrbl.org.", true),
        vec![
            ("zen.spamhaus.org.", true),
            ("bl.spamcop.net.", false),
            ("dnsbl-1.uceprotect.net.", true),
            ("pbsl.surriel.com.", false),
        ]
    }

    fn build_mx_dns() -> MxDns {
        let bootstrap: IpAddr = "8.8.8.8".parse().unwrap();
        let blocklists = blocklists()
            .iter()
            .map(|t| t.0)
            .collect::<Vec<&'static str>>();
        MxDns::with_dns(bootstrap, blocklists)
    }

    #[test]
    fn empty_blocklists() {
        let bootstrap: IpAddr = "8.8.8.8".parse().unwrap();
        let empty: Vec<String> = Vec::new();
        let mxdns = MxDns::with_dns(bootstrap, empty);
        let blocked = mxdns.is_blocked(Ipv4Addr::new(127, 0, 0, 2)).unwrap();
        assert_eq!(blocked, false);
    }

    #[cfg_attr(feature = "no-network-tests", ignore)]
    #[test]
    fn blocklist_addrs() {
        let mxdns = build_mx_dns();
        let dns_server: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let (bootstrap_task, bootstrap_client) = connect_client(dns_server);
        let mut runtime = Runtime::new().unwrap();
        runtime.spawn(bootstrap_task);
        let addrs = mxdns.blocklist_addrs(&mut runtime, bootstrap_client);
        let blocklists = blocklists();
        for i in 0..blocklists.len() {
            let b = blocklists[i];
            if b.1 {
                assert!(matches!(addrs[i], Some(_)), "no NS for {}", b.0);
            } else {
                assert!(matches!(addrs[i], None), "unexpected NS for {}", b.0);
            }
        }
    }

    #[cfg_attr(feature = "no-network-tests", ignore)]
    #[test]
    fn not_blocked() {
        let mxdns = build_mx_dns();
        let blocked = mxdns.is_blocked([127, 0, 0, 1]).unwrap();
        assert_eq!(blocked, false);
    }

    #[cfg_attr(feature = "no-network-tests", ignore)]
    #[test]
    fn blocked() {
        let mxdns = build_mx_dns();
        let blocked = mxdns.is_blocked([127, 0, 0, 2]).unwrap();
        assert_eq!(blocked, true);
    }

    #[cfg_attr(feature = "no-network-tests", ignore)]
    #[test]
    fn reverse_lookup() {
        let mxdns = build_mx_dns();
        let addr = "116.203.10.186".parse::<IpAddr>().unwrap();
        let reverse = mxdns.reverse_dns(addr).unwrap().unwrap();
        assert_eq!(reverse, "mail.alienscience.org.");
    }

    #[cfg_attr(feature = "no-network-tests", ignore)]
    #[test]
    fn fcrdns_ok() {
        let mxdns = build_mx_dns();
        let res = mxdns.fcrdns([116, 203, 3, 137]);
        assert!(
            matches!(res, Ok(FCrDNS::Confirmed(_))),
            "Valid mail server failed fcrdns: {:?}",
            res
        );
    }

    #[cfg_attr(feature = "no-network-tests", ignore)]
    #[test]
    fn fcrdns_google_ok() {
        let mxdns = build_mx_dns();
        let res = mxdns.fcrdns([209, 85, 167, 66]);
        assert!(
            matches!(res, Ok(FCrDNS::Confirmed(_))),
            "Valid google server failed fcrdns: {:?}",
            res
        );
    }

    #[cfg_attr(feature = "no-network-tests", ignore)]
    #[test]
    fn fcrdns_fail() {
        let mxdns = build_mx_dns();
        let res = mxdns.fcrdns([127, 0, 0, 2]);
        // 127.0.0.2 -> localhost -> 127.0.0.1
        assert!(
            matches!(res, Ok(FCrDNS::NoReverse) | Ok(FCrDNS::UnConfirmed(_))),
            "Known bad forward confirm failed: {:?}",
            res
        );
    }
}
