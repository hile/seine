#!/usr/bin/env python
"""
Parser for gTLD first level whois data formats
"""

import re,time

from seine.whois import WhoisError

SECTION_HEADERS = {
    'Domain name':          'domainname',
    'Registrant':           'registrant',
    'Trading as':           'trading_as',
    'Registrant type':      'registrant_type',
    "Registrant's address": 'registrant_address',
    'Registrar':            'registrar',
    'Relevant dates':       'dates',
    'Registration status':  'status',
    'Name servers':         'nameservers',
}

RE_NS_LIST = re.compile('(?P<ns>.*) (?P<addresses>.*)$')
TIME_FORMAT = lambda x: time.mktime(time.strptime(x,'%d-%b-%Y'))

def parse(domain,data):
    details = {}

    def next_section(name,section,value):
        if section is not None and value is not None:
            details[section] = value
        return (name,None)

    def push_value(value,new_value):
        if value is None:
            value = new_value 
        else:
            if type(value) != list:
                value = [value]
            value.append(new_value)
        return value

    section = None
    value = None
    for l in [l.strip() for l in data]:
        if l.startswith('% ') or l == '':
            continue
        l = l.decode('utf-8')

        if l[:20] == 'WHOIS lookup made at':
            break

        if l[-1]==':' and l[:-1] in SECTION_HEADERS.keys():
            (section,value) = next_section(SECTION_HEADERS[l[:-1]],section,value)
            continue

        if section == 'dates':
            try:
                timestamp = TIME_FORMAT(l[14:].strip())
            except ValueError:
                continue
            if l[:14] == 'Registered on:':
                field = 'created'
            if l[:13] == 'Renewal date:':
                field = 'expires'
            if l[:13] == 'Last updated:':
                field = 'modified'
            details[field] = timestamp

        elif section == 'nameservers':
            m = RE_NS_LIST.match(l)
            if m:
                ns = m.groupdict()['ns']
                details['glue_%s' % ns] = map(lambda x:
                    x.strip(),
                    m.groupdict()['addresses'].split(',')
                )
            else:
                ns = l
            value = push_value(value,ns)

        else:
            value = push_value(value,l)
            

    if section is not None and value is not None:
        details[section] = value

    return details

