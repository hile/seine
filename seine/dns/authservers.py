"""
DNS Zone authorized server processing classes
"""

from seine.dns import DNSError
from seine.dns.resolver import resolve_records, QueryError
from seine.dns.delegation import DNSZoneDelegation

class AuthorizedZoneServers(object):
    """DNS zone authorized servers

    Parser for authorized servers for DNS domain

    """
    def __init__(self, domain, rootfile='/tmp/db.root', timeout=5, ipv4=True, ipv6=False):
        self.domain = domain
        self.timeout = timeout

        self.SOA = {}
        self.NS  = {}

        if ipv4:
            self.ipv4_delegation = DNSZoneDelegation(
                domain, rrtype='A', rootfile=rootfile, timeout=timeout
            )
        else:
            self.ipv4_delegation = None

        if ipv6:
            self.ipv6_delegation = DNSZoneDelegation(
                domain, rrtype='AAAA', rootfile=rootfile, timeout=timeout
            )
        else:
            self.ipv6_delegation = None

    def update_delegations(self):
        """Update zone delegations

        Query and update delegations for zone

        """
        if self.ipv4_delegation is not None:
            self.ipv4_delegation.update_delegations()

        if self.ipv6_delegation is not None:
            self.ipv6_delegation.update_delegations()

    def query_server(self, server, rrtype):
        """Query RR for server

        Resolve this zone's RR from given server

        """
        return resolve_records(
            query=self.domain,
            rrtype=rrtype,
            nameserver=server,
            timeout=self.timeout
        )

    def validate_SOA(self):
        """Validate domain SOA

        Validate SOA record of a domain: this is only example stub right now!

        TODO - actually compare SOA records with each other

        """
        if not self.ipv4_delegation and not self.ipv6_delegation:
            self.update_delegations()

        soa_records = {}
        if self.ipv4_delegation is not None:
            for delegation in self.ipv4_delegation:
                if delegation.name not in soa_records.keys():
                    soa_records[delegation.name] = delegation.soa

        if self.ipv6_delegation is not None:
            for server in self.ipv6_delegation:
                if delegation.name not in soa_records.keys():
                    soa_records[delegation.name] = delegation.soa

        for server, server_soa in soa_records.items():
            for other, soa in soa_records.items():
                if server == other:
                    continue

                if server_soa != soa:
                    raise DNSError('SOA records do not match: %s and %s' % (server, delegation.soa))

    def validate_NS(self):
        """Validate zone NS records

        Validate NS records of a domain: this is only example stub right now!

        TODO - actually compare NS records with each other and TLD delegation

        """
        if self.ipv4_delegation:
            for delegation in self.ipv4_delegation:
                if self.ipv4_delegation.delegated_servers != delegation.nameservers:
                    raise DNSError('%s: servers from delegation and server differ: %s and %s' % (
                        delegation,
                        ','.join('%s' % s for s in self.ipv4_delegation.delegated_servers),
                        ','.join('%s' % s for s in delegation.nameservers)
                    ))

        if self.ipv6_delegation:
            for delegation in self.ipv6_delegation:
                if self.ipv6_delegation.delegated_servers != delegation.nameservers:
                    raise DNSError('%s: servers from delegation and server differ: %s and %s' % (
                        delegation,
                        ','.join('%s' % s for s in self.ipv6_delegation.delegated_servers),
                        ','.join('%s' % s for s in delegation.nameservers)
                    ))
