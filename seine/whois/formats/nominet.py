"""
Parser for nominet whois data formats
"""

import re
from datetime import datetime, date
from seine.whois.formats import WhoisDataParser, WhoisError

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

DATE_FIELD_MAP = {
    'Registered on:':   'created',
    'Renewal date:':    'expires',
    'Last updated:':    'modified',
}
DATE_PARSER = lambda value: datetime.strptime(value, '%d-%b-%Y').date()
# Registrations before good bookkeeping
OLD_DATE_BANNER = 'before Aug-1996'
OLD_DATE_VALUE = date(1996,8,01)

RE_NS_LIST = re.compile('(?P<ns>.*) (?P<addresses>.*)$')
END_HEADER_PREFIX = 'WHOIS lookup made at'

class nominet(WhoisDataParser):
    tlds = ( 'uk', )

    def parse(self, domain, data):
        """Parse data

        Parse Nominet whois data

        """

        def next_section(name, section, value):
            if section is not None and value is not None:
                self.set(section, value)
            return (name, None)

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

            if l[:len(END_HEADER_PREFIX)] == END_HEADER_PREFIX:
                break

            if l[-1]==':' and l[:-1] in SECTION_HEADERS.keys():
                (section, value) = next_section(SECTION_HEADERS[l[:-1]], section, value)
                continue

            if section == 'dates':
                for key, field in DATE_FIELD_MAP.items():
                    if l[:len(key)] == key:
                        datevalue = l[len(key):].strip()
                        if datevalue != OLD_DATE_BANNER:
                            datevalue =  DATE_PARSER(datevalue)
                        else:
                            datevalue = OLD_DATE_VALUE
                        self.set(field, datevalue)
                        break

            elif section == 'nameservers':
                m = RE_NS_LIST.match(l)
                if m:
                    ns = m.groupdict()['ns'].strip()
                    glue = [x.strip() for x in m.groupdict()['addresses'].split(',')]
                    self.set('glue_%s' % ns, glue)
                else:
                    ns = l.strip()
                value = push_value(value, ns)

            else:
                value = push_value(value, l)

        if section is not None and value is not None:
            self.set(section, value)

