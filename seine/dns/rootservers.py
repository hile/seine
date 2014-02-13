#!/usr/bin/env python
"""
Parse and fetch latest root servers database file.
"""

import os
import random
import requests

from seine.dns import DNSError
from seine.address import IPv4Address, IPv6Address

UPDATE_URLS = [
    'http://ftp.internic.net/domain/named.root',
    'htp://rs.internic.net/domain/named.root',
]


class RootServerAddressEntry(object):
    def __init__(self, server, address, expire):
        self.server = server
        if not isinstance(address, IPv4Address) and not isinstance(address, IPv6Address):
            raise ValueError('Unsupported address type: %s' % type(address))

        self.address_record = address
        self.expire = expire

    def __repr__(self):
        return self.address

    @property
    def address(self):
        if isinstance(self.address_record, IPv4Address):
            return self.address_record.ipaddress

        elif isinstance(self.address_record, IPv6Address):
            return self.address_record.address

class RootServer(object):
    """
    Represents one root server DNS name. Contains lists of IPv4 and
    IPv6 addresses with cache expiry times for each address associated
    to this server. The IPv4 and IPv6 servers can be accessed by the
    'A' and 'AAAA' keys.
    """
    def __init__(self, name, expire=0):
        self.name = name.lower()
        self.expire = expire
        self.ipv4_addresses = []
        self.ipv6_addresses = []

    def __repr__(self):
        return self.name

    def add(self, rrname, address, expire):
        """
        Adds a A or AAAA RR, associated address and cache expiry value
        to the server.
        """
        rrname = rrname.upper()
        if rrname == 'A':
            try:
                self.ipv4_addresses.append(RootServerAddressEntry(self, IPv4Address(address), expire))
            except ValueError:
                raise DNSError('Invalid IPv4 address: %s' % address)

        elif rrname == 'AAAA':
            try:
                self.ipv6_addresses.append(RootServerAddressEntry(self, IPv6Address('%s/128' % address), expire))
            except ValueError:
                raise DNSError('Invalid IPv6 address: %s' % address)

        else:
            raise DNSError('Unsupported root server address RR: %s' % rrname)


class RootServers(dict):
    """
    Loads, parses and updates the named.root offcial root server data
    file (if requested). Provides methods to list both IPv4 and IPv6
    root servers, by name or address.
    """
    def __init__(self, path):
        self.path = os.path.expandvars(os.path.expanduser(path))

        if os.path.isfile(self.path):
            self.parse()

    def __download_data__(self, update_urls=UPDATE_URLS):
        for url in update_urls:
            res = requests.get(url)
            if res.status_code != 200:
                continue

            return res.content

        raise DNSError('Error downloading root server list')

    def download(self, update_urls=UPDATE_URLS):
        """
        Downloads and replaces the named.root file from official sources.

        Replaces current status on the fly if download was successful.

        """
        data = self.__download_data__(update_urls)

        try:
            open(self.path, 'w').write(data)

        except IOError, (ecode, emsg):
            raise DNSError('Error writing %s: %s' % (self.path, emsg))
        except IOError, (ecode, emsg):
            raise DNSError('Error writing %s: %s' % (self.path, emsg))

        try:
            self.parse()

        except DNSError, emsg:
            raise DNSError('Update of root server list from %s failed: %s' % (self.path, emsg))

    def parse(self):
        """
        Load the root servers list from the file given when initializing.
        """
        self.clear()
        if not os.path.isfile(self.path):
            raise DNSError('No such file: %s' % self.path)

        for line in [l.strip() for l in open(self.path, 'r').readlines()]:
            if line[:1] in ( ';'):
                continue

            if line[:1] == '.':
                try:
                    (expire, rrclass, rrname, name) = line[1:].split(None, 3)
                except ValueError:
                    (expire, rrname, name) = line[1:].split(None, 2)

                if rrname != 'NS':
                    raise DNSError('Error parsing root servers file line: %s' % line)

                if name not in self:
                    self[name] = RootServer(name, expire)

            else:
                try:
                    (name, expire, rrname, address) = line.split()
                except ValueError:
                    raise DNSError('Error parsing root servers file line: %s' % line)

                if name not in self.keys():
                    raise DNSError('Unexpected server line: %s' % line)

                self[name].add(rrname, address, expire)

    @property
    def is_downloaded(self):
        return os.path.isfile(self.path)

    @property
    def ipv4_server_names(self):
        """
        Return names of IPv4 root servers (with A record)
        """
        return [k for k in self.keys() if self[k].ipv4_addresses]

    @property
    def ipv6_server_names(self):
        """
        Return names of IPv6 root servers (with AAAA record)
        """
        return [k for k in self.keys() if self[k].ipv6_addresses]

    @property
    def ipv4_server_addresses(self):
        """
        Return addresses of IPv4 root servers (with A record)
        """
        addresses = []
        for server in [s for s in self.values() if s.ipv4_addresses]:
            for addr in server.ipv4_addresses:
                if addr not in addresses:
                    addresses.append(addr)
        return addresses

    @property
    def ipv6_server_addresses(self):
        """
        Return addresses of IPv6 root servers (with AAAA record)
        """
        addresses = []
        for server in [s for s in self.values() if s.ipv6_addresses]:
            for addr in server.ipv6_addresses:
                if addr not in addresses:
                    addresses.append(addr)
        return addresses

    def random_rootserver(self, addresstype=IPv4Address):
        """Return random root server

        Optionally specify addresstype as ipv4 or ipv6 to return address
        of this type. Default is IPv4.

        """
        if addresstype in ('A', 'ipv4', IPv4Address):
            servers = self.ipv4_server_addresses
            addresstype = 'ipv4'
        elif addresstype in ('AAAA', 'ipv6', IPv6Address):
            servers = self.ipv6_server_addresses
            addresstype = 'ipv6'
        else:
            raise DNSError('Invalid addresstype argument: %s' % addresstype)

        if not servers:
            raise DNSError('Error choosing random server: no root servers matching %s available' & addresstype)
        return random.choice(servers)