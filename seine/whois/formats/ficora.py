#!/usr/bin/env python
"""
Parser for ficora whois data formats
"""

import re
from datetime import datetime
from seine.whois.formats import WhoisDataParser, WhoisError

FIELD_MAP = {
    'domain':           'domainname',
    'descr':            'owner',
    'address':          'address',
    'phone':            'telephone',
    'status':           'status',
    'nserver':          'nameservers',
    'created':          'created',
    'modified':         'updated',
    'expires':          'expires',
    'dnssec':           'dnssec',
}


RE_NS_STATUS = re.compile('(?P<ns>.*) \[(?P<status>.*)\]$')

DNS_FIELDS = ( 'nameservers', 'whois_servers', 'domainname', )
DATE_FIELDS = ( 'updated', 'created', 'expires', )
DATE_PARSER = lambda value: datetime.strptime(value, '%d.%m.%Y').date()

class ficora(WhoisDataParser):
    tlds = ( 'fi', )

    def parse(self, domain, data):
        data = WhoisDataParser.parse(self, domain, data)

        for l in data:
            if l.count(': ') == 0:
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

            elif k == 'nameservers':
                m = RE_NS_STATUS.match(v)
                if not m:
                    raise WhoisError('Error parsing line %s' % l)
                v = m.groupdict()['ns']

            elif k in DNS_FIELDS:
                v = v.lower()

            elif k == 'dnssec':
                v = v != 'no' and True or False

            self.set(k, v)

