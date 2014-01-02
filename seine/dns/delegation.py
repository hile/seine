"""
Module to query the DNS zone NS server delegation records starting
from DNS root servers.

Does not verify the delegation data. The DNSZoneDelegation object, when
initialized with query_ns_delegation, only tells the NS names and addresses
of registered nameservers for the domain.
"""

import logging
import random

from seine.dns import DNSError
from seine.dns.resolver import resolve_records
from seine.dns.rootservers import RootServers

class DNSZoneDelegation(list):
    """
    Class to fetch the DNS zone NS delegation details from root servers
    and from the TLD servers for given domain.

    Note that 'rootfile' must refere to a valid copy of db.root root
    server list. You can fetch a local copy from official sources with
    update() method of netutils.dnstools.rootservers.RootServers().
    """
    def __init__(self, domain, rrtype='A', rootfile='/tmp/db.root', timeout=5):
        """
        This class only checks for NS delegations with given rrtype: i.e.,
        if you want to check both IPv4 and IPv6 delegation, call this twice
        with rrtype='A' and rrtype='AAAA'. Don't change the attribute on the
        fly, it may break something.
        """
        self.domain = domain
        self.tld = '%s.' % self.domain.split('.')[-1]

        self.rootfile = rootfile
        self.timeout = int(timeout)

        if rrtype == 'A':
            self.address_type = 'IPv4'
        elif rrtype == 'AAAA':
            self.address_type = 'IPv6'
        else:
            raise ValueError('Invalid RR type: %s' % rrtype)

        self.rrtype = rrtype
        self.tld_servers = []

    def __str__(self):
        return '%s servers: %s' % (
            self.address_type,
            ','.join(s['address'] for s in self),
        )

    def query_root_servers(self):
        """
        Find the DNS TLD servers for the domain from root servers
        """

        self.tld_servers = []
        rootservers = RootServers(self.rootfile)

        if self.rrtype == 'A':
            servers = rootservers.ipv4_server_addresses()
        elif self.rrtype == 'AAAA':
            servers = rootservers.ipv6_server_addresses()

        if len(servers) == 0:
            raise DNSError('No root servers found!')

        server = servers[random.randint(0, len(servers)-1)]
        logging.debug('Querying NS %s for %s from %s' % (self.rrtype, self.tld, server))
        rs = resolve_records( query=self.tld,
            nameserver=server, rrtype='NS', timeout=self.timeout
        )

        tld_server_addresses = {}
        for entry in filter(lambda x: x['rrtype']==self.rrtype, rs['additional']):
            try:
                tld_server_addresses[entry['name']] = entry['address']
            except IndexError:
                raise DNSError('Additional data did not contain proper %s records' % self.rrtype)
        self.tld_servers = []
        for entry in filter(lambda x: x['rrtype']=='NS', rs['authority']):
            try:
                self.tld_servers.append(tld_server_addresses[entry['target']])
            except IndexError:
                logging.debug('TLD authorative answer did not contain glue address for server %s' % entry['target'])
                continue

    def query_ns_delegation(self):
        """
        Query zone delegation details from one of the TLD servers
        """
        self.__delslice__(0, len(self))

        self.query_root_servers()
        if len(self.tld_servers) == 0:
            raise DNSError('No TLD servers for %s' % self.domain)

        server = self.tld_servers[random.randint(0, len(self.tld_servers)-1)]

        logging.debug('Querying NS for %s from %s' % (self.domain, server))
        rs = resolve_records( query=self.domain,
            nameserver=server, rrtype='NS', timeout=self.timeout
        )

        reg_server_addresses = {}
        for entry in filter(lambda x: x['rrtype']==self.rrtype, rs['additional']):
            reg_server_addresses[entry['name']] = entry['address']
        for entry in filter(lambda x: x['rrtype']=='NS', rs['authority']):
            server = {'name': entry['target'] }
            try:
                server['address'] = reg_server_addresses[entry['target']]
            except IndexError:
                # Need to query address for server
                server['address'] = None
            self.append(server)

