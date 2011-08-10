
import logging

from seine.dns import DNSError
from seine.dns.resolver import resolve_records 
from seine.dns.delegation import DNSZoneDelegation 

class AuthorizedZoneServers(object):
    def __init__(self,domain,rootfile='/tmp/db.root',timeout=5,ipv4=True,ipv6=False):
        self.log = logging.getLogger('modules')

        self.domain = domain
        if ipv4 is True:
            self.v4_delegation = DNSZoneDelegation(domain,rrtype='A',
                rootfile=rootfile,timeout=timeout
            )
            self.v4_delegation.query_ns_delegation()
        else:
            self.v4_delegation = None

        if ipv6 is True:
            self.v6_delegation = DNSZoneDelegation(domain,rrtype='AAAA',
                rootfile=rootfile,timeout=timeout
            )
            self.v6_delegation.query_ns_delegation()
        else:
            self.v6_delegation = None

