#!/usr/bin/env python
"""
Parse and fetch latest root servers database file.
"""

import os,logging

from seine.dns import DNSError
from seine.address import IPv4Address,IPv6Address
from seine.url import HTTPRequest,HTTPRequestError 

UPDATE_URLS = [
    'ftp://ftp.internic.net/domain/named.root',
    'ftp://rs.internic.net/domain/named.root',
]

class RootServers(dict):
    """
    Loads, parses and updates the named.root offcial root server data
    file (if requested). Provides methods to list both IPv4 and IPv6
    root servers, by name or address.
    """
    def __init__(self,path):    
        self.path = path
        if os.path.isfile(path):
            self.load()

    def download(self):
        """
        Downloads and replaces the named.root file from official sources. 
        Replaces the process current status on the fly if download was 
        successful.
        """
        if os.path.isfile(self.path) and not os.access(self.path,os.W_OK):
            raise DNSError('Update not possible: no write permission to %s' % self.path)

        req = HTTPRequest()
        for url in UPDATE_URLS:
            try:
                code,data,headers = req.GET(url)
            except ValueError:
                continue
            try:
                open(self.path,'w').write(data)
                self.load()
                logging.info('Successfully updated %s from %s' % (self.path,url))
                return 
            except DNSError,e:
                raise DNSError('Update of %s failed: invalid data in file' % self.path)
            except IOError,(ecode,emsg):
                raise DNSError('Error writing %s: %s' % (self.path,emsg))
            except IOError,(ecode,emsg):
                raise DNSError('Error writing %s: %s' % (self.path,emsg))
        raise DNSError('Error updating %s: could not fetch and load new file' % self.path)

    def load(self):
        """
        Load the root servers list from the file given when initializing.
        """
        self.update({})
        if not os.path.isfile(self.path):
            raise DNSError('No such file: %s' % self.path)

        for l in open(self.path,'r').readlines():
            if l.startswith(';') or l.startswith('.'): 
                continue
            l = l.strip()
            try:
                (name,expire,rrname,address) = l.split()
            except ValueError:
                raise DNSError('Invalid line: %s' % l)
            if not self.has_key(name):
                self[name] = RootServer(name)
            self[name].add(rrname,address,expire)

    def ipv4_server_names(self):
        """
        Return names of IPv4 root servers (with A record)
        """
        return filter(lambda k: self[k].has_key('A'), self.keys()) 

    def ipv4_server_addresses(self):
        """
        Return addresses of IPv4 root servers (with A record)
        """
        addresses = []
        for server in self.ipv4_server_names():
            for address in self[server].ipv4_addresses():
                if addresses.count(address) == 0:
                    addresses.append(address)
        return addresses
    
    def ipv6_server_names(self):
        """
        Return names of IPv4 root servers (with AAAA record)
        """
        return filter(lambda k: self[k].has_key('AAAA'), self.keys()) 

    def ipv6_server_addresses(self):
        """
        Return addresses of IPv6 root servers (with AAAA record)
        """
        addresses = []
        for server in self.ipv6_server_names():
            for address in self[server].ipv6_addresses():
                if addresses.count(address) == 0:
                    addresses.append(address)
        return addresses
class RootServer(dict):
    """
    Represents one root server DNS name. Contains lists of IPv4 and 
    IPv6 addresses with cache expiry times for each address associated
    to this server. The IPv4 and IPv6 servers can be accessed by the 
    'A' and 'AAAA' keys.
    """
    def __init__(self,name):
        self.name = name.lower()
    
    def add(self,rrname,address,expire):
        """
        Adds a A or AAAA RR, associated address and cache expiry value
        to the server.
        """
        rrname = rrname.upper()
        if rrname == 'A':
            try:
                address = IPv4Address(address).ipaddress
            except ValueError:
                raise DNSError('Invalid address: %s' % address)
        elif rrname == 'AAAA':
            try:
                address = IPv6Address('%s/128' % address).address
            except ValueError:
                raise DNSError('Invalid address: %s' % address)
        else:
            raise DNSError('Unsupported RR: %s' % rrname)
                
        if not self.has_key(rrname):
            self[rrname] = []
        self[rrname].append({'address': address,'expire': expire})

    def ipv4_addresses(self):
        """
        Returns list of IPv4 addresses for this server
        """
        if self.has_key('A'):
            return [x['address'] for x in self['A']]            
        return []

    def ipv6_addresses(self):
        """
        Returns list of IPv6 addresses for this server
        """
        if self.has_key('AAAA'):
            return [x['address'] for x in self['AAAA']]
        return []

