#!/usr/bin/env python

import logging

from seine.dns.resolver import resolve_records,QueryError
from seine.dns.delegation import DNSZoneDelegation 

class AuthorizedZoneServers(dict):
    def __init__(self,domain,rootfile='/tmp/db.root',timeout=5,ipv4=True,ipv6=False):
        self.domain = domain
        self.timeout = timeout

        self.log = logging.getLogger('modules')

        self.delegations = {}
        self.SOA = {}
        self.NS  = {}

        if ipv4 is True:
            self.delegations['IPv4'] = DNSZoneDelegation(domain,
                rrtype='A', rootfile=rootfile, timeout=timeout
            )

        if ipv6 is True:
            self.delegations['IPv6'] = DNSZoneDelegation(domain,
                rrtype='AAAA', rootfile=rootfile, timeout=timeout
            )
    
    def update_delegations(self):
        for k,delegation in self.delegations.items():
            if delegation is None:
                continue
            self.log.debug('Updating %s %s delegations' % (self.domain,k))
            delegation.query_ns_delegation()

    def query_server(self,server,rrtype):
        self.log.debug('Querying %s records from %s' % (rrtype,server))
        return resolve_records(
            query=self.domain,rrtype=rrtype,
            nameserver=server,timeout=self.timeout
        )

    def validate_SOA(self):
        for addrtype,delegation in self.delegations.items():
            self.log.debug('Checking %s SOA records' % (addrtype))
            for s in [s['address'] for s in delegation]:
                self.SOA[s] = self.query_server(s,'SOA')
                for r in self.SOA[s]['results']:
                    print r
            # TODO - actually compare SOA records with each other

    def validate_NS(self):
        for addrtype,delegation in self.delegations.items():
            self.log.debug('Checking %s NS records' % (addrtype))
            for s in [s['address'] for s in delegation]:
                self.NS[s] = self.query_server(s,'NS')
                for r in self.NS[s]['results']:
                    print r
            # TODO - actually compare NS records with each other and 
            # with the TLD delegation records

