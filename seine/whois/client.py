#!/usr/bin/env python
"""
Nagios test module to query whois servers for a domain's data,
use by libexec/check_whois script to check expiration status.
"""

import sys,os,logging,time
import socket,select

from seine.address import IPv4Address,IPv6Address
from seine.whois import WhoisError
from seine.whois.servers import WhoisServerCache
from seine.whois.parsers import WhoisData

WHOIS_PORT = 43
WHOIS_SERVER_TIMEOUT = 15
WHOIS_BUFFER_SIZE = 1024

TLD_REQUIRES_EQUALS = ['com']

class WhoisEntry(object):
    def __init__(self,domain,timeout=WHOIS_SERVER_TIMEOUT):
        self.domain = domain
        self.cache = WhoisServerCache()
        self.timeout = timeout

        tld = domain.split('.')[-1]
        self.server = self.cache.resolve(tld,timeout=timeout)

        self.__addresses = []

    def __str__(self):
        return '%s: whois server: %s' % (self.domain,self.server.address)

    def __whois_request__(self,address):
        if address in self.__addresses:
            raise WhoisError('Whois server loop detected')
        self.__addresses.append(address)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:
            try:
                s.connect((address,WHOIS_PORT))
            except socket.error,(ecode,reason):
                if ecode in [errno.EINPROGRESS,errno.EALREADY]: 
                    continue
                else: 
                    raise WhoisError(
                        'Error connecting to %s: %s' % (address,reason)
                    )
            break

        ret = select.select ([s], [s], [], 5)
        if len(ret[1])== 0 and len(ret[0]) == 0:
            s.close()
            raise WhoisError('Timeout waiting for data from %s' % address)

        s.setblocking(1)
        s.settimeout(self.timeout)
        if self.server.tld in TLD_REQUIRES_EQUALS:
            s.send('=%s\r\n' % self.domain)
        else:
            s.send('%s\r\n' % self.domain)

        out = ''
        while True:
            try:
                data = s.recv(WHOIS_BUFFER_SIZE)
            except socket.timeout:
                s.close()
                raise WhoisError('Request timeout to %s' % address)
            except socket.error, (ecode, reason):
                if ecode in [errno.EINPROGRESS,errno.EALREADY]:
                    continue
                else:
                    s.close()
                    raise WhoisError(
                        'Error reading data from %s: %s' % (address,reason)
                    )
            # End of data
            if not data: 
                break
            out += data
        s.close()

        if out.count('\r\n') > 0:
            return out.split('\r\n')
        else:
            return out.split('\n')

    def query(self):
        """
        Send a whois query for the domain to given server: to detect whois
        server loops, tracks the IP address of server
        """
        return self.__whois_request__(self.server.address)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    for d in sys.argv[1:]:
        try:
            entry = WhoisEntry(d)
            open('/tmp/whois-%s.txt' % d,'w').write('\n'.join(entry.query()))
            continue
            entry.checkExpiry(warning=30,critical=60)
            print int(entry.status),entry.status
        except WhoisError,e:
            print e
            

