#!/usr/bin/env python
"""
Cache for whois server lists.
"""

import sys,os,logging,time
import socket,select

import ConfigParser

from seine.address import IPv4Address,IPv6Address
from seine.dns.tld import TLDCache,DNSCacheError
from seine.whois import WhoisError

SERVER_CACHE = os.path.join(os.getenv('HOME'),'.whoisservers.cache')

SEARCH_DOMAIN = 'whois-servers.net'

WHOIS_PORT = 43
WHOIS_SERVER_TIMEOUT = 15
WHOIS_BUFFER_SIZE = 1024

class WhoisServerCache(list):
    def __init__(self,cache_path=None):
        self.tlds = TLDCache()
        self.cache_path = cache_path is not None and cache_path or SERVER_CACHE
        self.log = logging.getLogger('modules')

        try:
            self.tlds = TLDCache()
            self.tlds.load()
        except DNSCacheError,emsg:
            raise WhoisEror(emsg) 

        try:
            self.cache = ConfigParser.ConfigParser()
            self.cache.read(self.cache_path)
        except OSError,(ecode,emsg):
            raise WhoisError(emsg) 
        except IOError,e:
            raise WhoisError(e[1])

    def __getitem__(self,item):
        if self.cache.has_section(item):
            entry = dict(self.cache.items(item))
            return WhoisServer(item,entry['address'])
        raise KeyError('No such WhoisServerCache item: %s' % item)

    def has_key(self,item):
        return self.cache.has_section(item)

    def update(self,tld,address=None):
        if not self.cache.has_section(tld):
            self.cache.add_section(tld)
        if address:
            self.cache.set(tld,'address',address)

        cache_dir = os.path.dirname(self.cache_path)
        if not os.path.isdir(cache_dir):
            try:
                os.makedirs(cache_dir)
            except IOError,(ecode,emsg):
                raise WhoisError(
                    'Error creating cache directory %s: %s' % (cache_dir,emsg)
                )
            except OSError,(ecode,emsg):
                raise WhoisError(
                    'Error creating cache directory %s: %s' % (cache_dir,emsg)
                )

        try:
            self.cache.write(open(self.cache_path,'w'))
        except OSError,(ecode,emsg):
            raise WhoisError('Error updating cache %s: %s' % (self.cache_path,emsg))
        except IOError,e:
            raise WhoisError('Error updating cache %s: %s' % (self.cache_path,e[1]))

    def resolve(self,tld,timeout=WHOIS_SERVER_TIMEOUT):
        try:
            self.tlds[tld]
        except KeyError:
            raise WhoisError('Invalid TLD name: %s' % tld)

        try:
            return self[tld]
        except KeyError:
            try:
                timeout = int(timeout)
            except ValueError:
                raise WhoisError('Invalid timeout value: %s' % timeout)
            details = {}
            name = '.'.join([tld,SEARCH_DOMAIN])
            self.log.debug('Resolving: %s' % name)
            try:
                socket.setdefaulttimeout(timeout)
                address = socket.gethostbyname(name)
                details['address'] = IPv4Address(address).address
                self.update(tld,address)
            except socket.timeout:
                raise WhoisError('Timeout resolving whois server %s' % name)
            except socket.gaierror,(ecode,emsg):
                raise WhoisError(emsg)
            except ValueError:
                raise WhoisError('Invalid whois server address: %s' % address)
        return self[tld]

class WhoisServer(dict):
    def __init__(self,tld,address):
        self.tld = tld
        self.address = address

    def __str__(self):
        return 'TLD .%s whois server: %s' % (self.tld,self.address)

if __name__ == '__main__':
    c = WhoisServerCache()
    for k in sys.argv[1:]:
        try:
            print c.resolve(k)
        except WhoisError,emsg:
            print emsg

