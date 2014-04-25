#!/usr/bin/env python
"""
Parser for saudinic whois data formats
"""

import re
from datetime import datetime
from seine.whois.formats import WhoisDataParser, WhoisError

FIELD_MAP = {
    'Domain Name':      'domainname',
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

RE_NS_LIST = re.compile('(?P<ns>.*) \((?P<addresses>.*)\)$')

DATE_FIELDS = ( 'updated', 'created', 'expires', )
DATE_PARSER = lambda value: datetime.strptime(value, '%d.%m.%Y').date()


class saudinic(WhoisDataParser):
    tlds = ( 'sa', )

    def parse(self, domain, data):
        """Parse data

        Parse SaudiNIC whois data

        """
        def next_section(name, section, value):
            if section is not None and value is not None:
                self.set(section, value)
            return (name,None)

        def push_value(value, new_value):
            if value is None:
                value = new_value
            else:
                if type(value) != list:
                    value = [value]
                value.append(new_value)
            return value

        data = WhoisDataParser.parse(self, domain, data)

        section = None
        value = None
        for l in [l.strip() for l in data]:
            if l.startswith('% ') or l == '':
                continue
            l = l.decode('utf-8')

            if l[:12] == 'Domain Name:':
                self.set('domainname', l[12:].lstrip())
                continue

            if l == 'Registrant:':
                (section, value) = next_section('registrant', section, value)
                continue

            if l == 'Administrative Contact:':
                (section, value) = next_section('admin_contact', section, value)
                continue

            if l == 'Technical Contact:':
                (section, value) = next_section('technical_contact', section, value)
                continue

            if l == 'Name Servers:':
                (section, value) = next_section('nameservers', section, value)
                continue

            if l[:11] == 'Created on:':
                self.set('created', datetime.strptime(l[12:], '%Y-%m-%d').date())
                continue
            if l[:16] == 'Last Updated on:':
                self.set('modified', datetime.strptime(l[17:], '%Y-%m-%d').date())
                continue

            if section == 'registrant':
                if l[:8] == 'Address:':
                    (section, value) = next_section('registrant_address', section, value)
                    value = l[9:]
                    continue
                else:
                    value = push_value(value, l)

            if section == 'admin_contact':
                if l[:8] == 'Address:':
                    (section, value) = next_section('admin_address', section, value)
                    value = l[9:]
                    continue
                else:
                    value = push_value(value, l)

            if section == 'technical_contact':
                if l[:8] == 'Address:':
                    (section, value) = next_section('technical_address', section, value)
                    value = l[9:]
                    continue
                else:
                    value = push_value(value, l)

            if section in ( 'registrant_address', 'admin_address', 'technical_address', ):
                value = push_value(value, l)

            elif section == 'nameservers':
                m = RE_NS_LIST.match(l)
                if m:
                    ns = m.groupdict()['ns'].strip()
                    glue = [x.strip() for x in m.groupdict()['addresses'].split(',')]
                    self.set('glue_%s' % ns, glue)
                else:
                    ns = l.strip()

                value = push_value(value, ns)

        if section is not None and value is not None:
            self.set(section, value)

