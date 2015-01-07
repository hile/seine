#!/usr/bin/env python
"""
Parser for gTLD first level whois data formats
"""

from datetime import datetime

from seine.whois.formats import WhoisDataParser, WhoisError

FIELD_MAP = {
    'Domain Name':      'domainname',
    'Registrar':        'registrar',
    'Whois Server':     'whois_servers',
    'Referral URL':     'referral_url',
    'Name Server':      'nameservers',
    'Status':           'status',
    'Updated Date':     'updated',
    'Creation Date':    'created',
    'Expiration Date':  'expires',
    'Sponsoring Registrar IANA ID': 'sponsor',
}

DNS_FIELDS = ( 'nameservers', 'whois_servers', 'domainname', )
DATE_FIELDS = ( 'updated', 'created', 'expires', )
DATE_PARSER = lambda value: datetime.strptime(value, '%d-%b-%Y').date()

class gtld(WhoisDataParser):
    tlds = ( 'com', 'edu', 'gov', 'mil', 'net', 'org', 'arpa', )

    def parse(self, domain, data):
        data = WhoisDataParser.parse(self, domain, data)

        for l in data:
            if not l.startswith(' ') or l.strip()=='':
                continue

            try:
                k, v = [x.strip() for x in l.split(':', 1)]
            except ValueError:
                raise WhoisError('Error parsing line %s' % l)

            try:
                k = FIELD_MAP[k]
            except KeyError:
                raise WhoisError('Unknown field on line %s' % l)

            if k in DATE_FIELDS:
                v = DATE_PARSER(v)

            elif k in DNS_FIELDS:
                v = v.lower()

            self.set(k, v)
