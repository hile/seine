
import os
import re
import requests

from seine.address import EthernetMACAddress

OUI_URL = 'http://standards.ieee.org/develop/regauth/oui/oui.txt'
OUI_CACHE_PATH = os.path.expanduser('~/.oiu.cache')

HEX_LINE = re.compile('\s+(?P<prefix>[A-Z0-9-]+)\s+\(hex\)\s+(?P<company>.*)$')
BASE_16_LINE = re.compile('\s+(?P<prefix>[A-Z0-9]+)\s+\(base 16\)\s+(?P<company>.*)$')


class OUIPrefix(object):
    def __init__(self, prefix, company):
        self.prefix = ':'.join(prefix.split('-')).upper()
        self.company = company
        self.address = []

    def __repr__(self):
        return '%s %s' % (self.company, ', '.join(self.address))


class OUIPrefixLookup(dict):
    def __init__(self, path=OUI_CACHE_PATH):
        self.path = path
        if not os.path.isfile(self.path):
            self.update()

        entry = None
        for l in [x.rstrip() for x in open(self.path, 'r').readlines()]:
            if l.strip() == '' or  BASE_16_LINE.match(l):
                continue

            m = HEX_LINE.match(l)
            if m:
                entry = OUIPrefix(**m.groupdict())
                self[entry.prefix] = entry
                continue

            elif entry:
                entry.address.append(l.strip())

    def update(self):
        res = requests.get(OUI_URL)
        open(self.path, 'w').write(res.content)

    def match(self, address):
        if not isinstance(address, EthernetMACAddress):
            address = EthernetMACAddress(address)

        parts = address.address.upper().split(':')
        while parts:
            key = ':'.join(parts)
            if key in self:
                return self[key]
            parts.pop()

        return None

