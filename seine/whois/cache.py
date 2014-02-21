#!/usr/bin/env python
"""
Cache for whois server lists.
"""

import sys
import os
import time
import logging
import random

import errno
import socket
import select

import ConfigParser

from seine.address import IPv4Address, IPv6Address
from seine.dns.tld import TLDCache, DNSCacheError
from seine.whois import WhoisError

CACHE_FILES = (
    '/var/cache/whois/servers.cache',
    '/tmp/whois-%s/servers.cache' % os.geteuid(),
)
SEARCH_DOMAIN = 'whois-servers.net'

WHOIS_PORT = 43
WHOIS_SERVER_TIMEOUT = 15
WHOIS_BUFFER_SIZE = 1024

TLD_REQUIRES_EQUALS = ['com']

logger = logging.getLogger(__file__)


class WhoisServer(object):
    def __init__(self, tld, address, timeout=WHOIS_SERVER_TIMEOUT):
        self.tld = tld
        self.address = address
        self.timeout = float(timeout)
        self.socket = None

    def __del__(self):
        self.close()

    def close(self):
        if self.socket is not None:
            self.socket.close()
        self.socket = None

    def connect(self):
        raise NotImplementedError('Must be implemented in child class')

    def send_query(self, domain):
        raise NotImplementedError('Must be implemented in child class')

    def get_response(self, buffer_size=WHOIS_BUFFER_SIZE):
        raise NotImplementedError('Must be implemented in child class')


class IPv4WhoisServer(WhoisServer):
    def connect(self):
        if self.socket is not None:
            raise WhoisError('Connection already open to %s' % self.address)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:
            try:
                self.socket.connect((self.address, WHOIS_PORT))
            except socket.error, (ecode, emsg):
                if ecode in [errno.EINPROGRESS, errno.EALREADY]:
                    continue
                else:
                    raise WhoisError('Error connecting to %s: %s' % (self.address, emsg) )
            break

        ret = select.select([self.socket], [self.socket], [], 5)
        if len(ret[1]) == 0 and len(ret[0]) == 0:
            self.close()
            raise WhoisError('Timeout waiting for data from %s' % self.address)

    def send_query(self, domain):
        if self.socket is None:
            raise WhoisError('Connection not open to %s' % self.address)

        self.socket.setblocking(1)
        self.socket.settimeout(self.timeout)

        if self.tld in TLD_REQUIRES_EQUALS:
            data = '=%s\r\n' % domain
        else:
            data = '%s\r\n' % domain

        self.socket.send(data)

    def get_response(self, buffer_size=WHOIS_BUFFER_SIZE):
        if self.socket is None:
            raise WhoisError('Connection not open to %s' % self.address)

        out = ''
        while True:
            try:
                data = self.socket.recv(WHOIS_BUFFER_SIZE)
            except socket.timeout:
                self.close()
                raise WhoisError('Request timeout to %s' % self.address)
            except socket.error, (ecode, emsg):
                if ecode in [errno.EINPROGRESS, errno.EALREADY]:
                    continue
                else:
                    self.close()
                    raise WhoisError('Error reading data from %s: %s' % (self.address, emsg))

            # End of data
            if not data:
                break

            out += data

        self.close()

        return out


class IPv6WhoisServer(WhoisServer):
    def connect(self):
        raise NotImplementedError('IPv6 whois queries not yet implemented')

    def send(self, s, data):
        raise NotImplementedError('IPv6 whois queries not yet implemented')

    def get_response(self, s, buffer_size=WHOIS_BUFFER_SIZE):
        raise NotImplementedError('IPv6 whois queries not yet implemented')


class TLDWhoisServerList(object):
    def __init__(self, tld, ipv4_addresses=[], ipv6_addresses=[]):
        self.tld = tld
        self.ipv4_addresses = [IPv4Address(address) for address in ipv4_addresses]
        self.ipv6_addresses = [IPv6Address(address) for address in ipv6_addresses]

    def __repr__(self):
        return 'TLD .%s whois servers: %s %s' % (
            self.tld,
            ','.join(x.ipaddress for x in self.ipv4_addresses),
            ','.join(x.address for x in self.ipv6_addresses),
        )

    def query(self, name, ipv4=True, ipv6=False):
        if ipv4:
            if not self.ipv4_addresses:
                raise WhoisError('No IPv4 addresses for %s whois servers' % self.tld)
            server = IPv4WhoisServer(self.tld, random.choice(self.ipv4_addresses).ipaddress)

        elif ipv6:
            if not self.ipv6_addresses:
                raise WhoisError('No IPv6 addresses for %s whois servers' % self.tld)
            server = IPv6WhoisServer(random.choice(self.ipv6_addresses).address)

        tld = name.rstrip('.').split('.')[-1]
        if tld != self.tld:
            raise WhoisError('TLD %s does not match server: %s' % (tld, self.tld))

        server.connect()
        server.send_query(name)
        return server.get_response()

class WhoisServerCache(dict):
    def __init__(self, cache_path=None, tld_cache_path=None):
        self.cache_path = None

        if cache_path is not None:
            self.cache_path = os.path.expandvars(os.path.expanduser(cache_path))

        else:
            for f in CACHE_FILES:
                if os.path.isfile(f) and os.access(f, os.W_OK):
                    self.cache_path = f
                    break

                fdir = os.path.dirname(f)
                if not os.path.isdir(fdir):
                    try:
                        os.makedirs(os.path.dirname(f))
                    except IOError, (ecode, emsg):
                        continue
                    except OSError, (ecode, emsg):
                        continue

                if not os.path.isfile(f):
                    try:
                        open(f, 'w').write('\n')
                        os.unlink(f)
                        self.cache_path = f
                        break
                    except IOError, (ecode, emsg):
                        continue
                    except OSError, (ecode, emsg):
                        continue

        if self.cache_path is None:
            raise WhoisError('ERROR: No whois cache path defined')

        try:
            self.tlds = TLDCache(tld_cache_path)
            if not self.tlds.is_downloaded:
                self.tlds.download()
        except DNSCacheError, emsg:
            raise WhoisEror(emsg)

        if os.path.isfile(self.cache_path):
            self.load()

    def load(self):
        if not os.path.isfile(self.cache_path):
            raise WhoisError('No such file: %s' % self.cache_path)

        try:
            cache = ConfigParser.ConfigParser()
            cache.read(self.cache_path)
        except OSError, (ecode, emsg):
            raise WhoisError(emsg)
        except IOError, (ecode, emsg):
            raise WhoisError(emsg)

        for tld in cache.sections():
            try:
                ipv4_addresses = []
                ipv6_addresses = []
                if cache.has_option(tld, 'ipv4_addresses') and cache.get(tld, 'ipv4_addresses'):
                    ipv4_addresses.extend(cache.get(tld, 'ipv4_addresses').split(','))
                if cache.has_option(tld, 'ipv6_addresses') and cache.get(tld, 'ipv6_addresses'):
                    ipv6_addresses.extend(cache.get(tld, 'ipv6_addresses').split(','))
                entry = TLDWhoisServerList(tld, ipv4_addresses, ipv6_addresses)
                self[tld] = entry
            except ConfigParser.NoOptionError, emsg:
                logger.debug('Invalid cache entry for %s' % tld)

    def save(self):
        if len(self) == 0:
            return

        cache_dir = os.path.dirname(self.cache_path)

        if not os.path.isdir(cache_dir):
            try:
                os.makedirs(cache_dir)
            except IOError, (ecode, emsg):
                raise WhoisError('Error creating cache directory %s: %s' % (cache_dir, emsg))
            except OSError, (ecode, emsg):
                raise WhoisError('Error creating cache directory %s: %s' % (cache_dir, emsg))

        try:
            cache = ConfigParser.ConfigParser()
            for entry in self.values():
                section = cache.add_section(entry.tld)
                cache.set(entry.tld, 'ipv4_addresses', ','.join(x.ipaddress for x in entry.ipv4_addresses))
                cache.set(entry.tld, 'ipv6_addresses', ','.join(x.address for x in entry.ipv6_addresses))
            cache.write(open(self.cache_path, 'w'))

        except OSError, (ecode, emsg):
            raise WhoisError('Error updating cache %s: %s' % (self.cache_path, emsg))
        except IOError, (ecode, emsg):
            raise WhoisError('Error updating cache %s: %s' % (self.cache_path, emsg))

    def get(self, tld, timeout=WHOIS_SERVER_TIMEOUT):
        try:
            timeout = int(timeout)
        except ValueError:
            raise WhoisError('Invalid timeout value: %s' % timeout)

        if tld not in self.tlds:
            raise WhoisError('Invalid TLD name: %s' % tld)

        if tld not in self:
            details = {}
            name = '.'.join([tld, SEARCH_DOMAIN])
            try:
                socket.setdefaulttimeout(timeout)
                name, aliases, addresses = socket.gethostbyname_ex(name)
                entry = TLDWhoisServerList(tld, addresses)
                self[tld] = entry

            except socket.timeout:
                raise WhoisError('Timeout resolving whois server %s' % name)
            except socket.gaierror, (ecode, emsg):
                raise WhoisError(emsg)
            except ValueError, emsg:
                raise WhoisError(emsg)

        return self[tld]

    def query(self, name):
        try:
            tld = name.rstrip('.').split('.')[-1]
        except ValueError:
            raise WhoisError('Error parsing TLD from %s' % name)

        tldservers = self.get(tld)
        return tldservers.query(name)
