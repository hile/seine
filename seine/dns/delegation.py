"""
Module to query the DNS zone NS server delegation records starting
from DNS root servers.
"""

import random

from seine.dns import DNSError
from seine.address import IPv4Address, IPv6Address
from seine.dns.resolver import resolve_records
from seine.dns.rootservers import RootServers

class SOA(object):
    def __init__(self, server, domain):
        self.server = server
        self.domain = domain

        res = resolve_records(self.domain, self.server, 'SOA')
        if len(res['results']) != 1:
            raise ValueError('Invalid SOA query result: %s' % res['results'])
        data = res['results'][0]

        if data['rrtype'] != 'SOA':
            raise ValueError('Response is not a SOA record')

        name = '%s' % data['name']
        if self.domain != name:
            raise ValueError('Received SOA name %s expected %s' % (name, self.domain))

        self.master_server = '%s' % data['mname']
        self.rname = '%s' % data['rname']

        for field in ('serial', 'refresh', 'retry', 'expire', 'minimum'):
            if field not in data.keys():
                raise ValueError('Invalid SOA query result: missing %s' % field)
            setattr(self, field, data[field])

    def __repr__(self):
        return '%s serial %d refresh %d retry %d expire %d minimum %d contact %s' % (
            self.domain,
            self.serial,
            self.refresh,
            self.retry,
            self.expire,
            self.minimum,
            self.rname
        )

    def __cmp__(self, other):
        """Compare SOA records

        Please note we do NOT compare server from which the record originates from: identical
        SOA records are expected from multiple sources

        """
        if not isinstance(other, SOA):
            raise ValueError('Compared target must be SOA instance: %s' % type(other))

        if self.master_server != other.master_server:
            return cmp(self.master_server, other.master_server)

        if self.domain != other.domain:
            return cmp(self.domain, other.domain)

        if self.rname != other.rname:
            return cmp(self.rname, other.rname)

        for field in ('serial', 'refresh', 'retry', 'expire', 'minimum'):
            a = getattr(self, field)
            b = getattr(other, field)
            if a != b:
                return cmp(a, b)

        return 0

    def __eq__(self, other):
        return self.__cmp__(other) == 0

    def __ne__(self, other):
        return self.__cmp__(other) != 0

    def __lt__(self, other):
        return self.__cmp__(other) < 0

    def __lte__(self, other):
        return self.__cmp__(other) <= 0

    def __gt__(self, other):
        return self.__cmp__(other) > 0

    def __gte__(self, other):
        return self.__cmp__(other) >= 0

    @property
    def email(self):
        try:
            address, domain = self.rname.split('.', 1)
            return '%s@%s' % (address, domain.rstrip('.'))
        except ValueError:
            return None

    def validate(self):
        """Validate SOA

        Validate time values in SOA record

        """
        errors = []
        warnings = []
        if self.refresh < 0:
            errors.append('Invalid refresh value: %s' % refresh)

        if self.email is None:
            warnings.append('Error parsing email address from %s' % self.rname)

        if self.expire <= self.refresh:
            errors.append('Zone expire <= refresh: %s %s' % (self.expire, self.refresh))

        if self.expire <= self.retry:
            errors.append('Zone expire <= retry: %s %s' % (self.expire, self.retry))

        if self.refresh < self.minimum:
            warnings.append('Zone refresh time is smaller than minimum TTL: %s %s' % (self.refresh, self.minimum))

        return errors, warnings

class DelegateServer(object):
    def __init__(self, delegation, rrtype, name, address):
        self.delegation = delegation
        self.rrtype = rrtype
        self.name = name
        self.address = address

    def __repr__(self):
        return self.hostname

    @property
    def hostname(self):
        return '%s' % self.name.__str__().rstrip('.')

    @property
    def domain(self):
        return '%s.' % self.delegation.domain

    @property
    def soa(self):
        try:
            return SOA(self.address, self.domain)
        except ValueError, emsg:
            raise DNSError('Error retrieving SOA for %s from %s: %S' % (self.address, self.domain, emsg))

    @property
    def nameservers(self):
        addresses = []
        res = resolve_records(self.domain, self.address, 'NS')
        for r in res['results']:
            if r['rrtype'] != 'NS':
                continue

            server = '%s' % r['target']
            addresses.append(server.rstrip('.'))

        return addresses

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
            ','.join(self.delegated_servers),
        )

    @property
    def delegated_servers(self):
        return [s.hostname for s in self]

    def update_tld_rootservers(self):
        """
        Find the DNS TLD servers for the domain from root servers
        """

        self.tld_servers = []
        rootservers = RootServers(self.rootfile)
        if not rootservers.is_downloaded:
            rootservers.download()

        server = rootservers.random_rootserver(self.rrtype).address
        rs = resolve_records(query=self.tld, nameserver=server, rrtype='NS', timeout=self.timeout)

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
                continue

    def update_delegations(self):
        """
        Query zone delegation details from one of the TLD servers
        """
        self.__delslice__(0, len(self))

        self.update_tld_rootservers()
        if len(self.tld_servers) == 0:
            raise DNSError('No TLD servers for %s' % self.domain)
        server = self.tld_servers[random.randint(0, len(self.tld_servers)-1)]

        rs = resolve_records( self.domain, server, 'NS', self.timeout)

        reg_server_addresses = {}
        for entry in filter(lambda x: x['rrtype']==self.rrtype, rs['additional']):
            reg_server_addresses[entry['name']] = entry['address']

        for entry in filter(lambda x: x['rrtype']=='NS', rs['authority']):
            try:
                address = reg_server_addresses[entry['target']]
            except IndexError:
                # Need to query address for server
                address = None

            self.append(DelegateServer(self, self.rrtype, entry['target'], address ))
