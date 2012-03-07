#!/usr/bin/env python
"""
Parser for gTLD first level whois data formats
"""

import time

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
}

DNS_FIELDS = ['nameservers','whois_servers','domainname']

DATE_FIELDS = ['updated','created','expires']
DATE_PARSER = lambda x: time.mktime(time.strptime(x,'%d-%b-%Y'))

def parse(domain,data):
    details = {}
    for l in data:
        if not l.startswith(' '):
            continue
        try:
            k,v = [x.strip() for x in l.split(':',1)]
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
        if details.has_key(k):
            if type(details[k]) != list:
                details[k] = [details[k]]
            details[k].append(v)
        else:
            details[k] = v
    return details

