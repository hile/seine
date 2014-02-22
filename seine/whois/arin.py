"""
Reverse IP delegation parser from ARIN
"""

import requests
import json
import logging

from dateutil.parser import parse as dateparser
from seine.whois import WhoisError
from seine.address import IPv4Address, IPv6Address
from systematic.log import Logger

URL_TEMPLATE = 'http://whois.arin.net/rest/ip/%(address)s'

DATE_FIELD_MAP = {
    'registered': 'registrationDate',
    'updated': 'updateDate',
}

logger = Logger().default_stream

class ARINNetBlock(object):
    """Netblock entry

    Netblock entry in ARINReverseIP results

    """
    def __init__(self, reverse, data):
        self.reverse = reverse
        block = data['netBlock']
        self.description = block['description']['$']
        self.type = block['type']['$']

        self.mask = int(block['cidrLength']['$'])

        if reverse.address_format == IPv4Address:
            self.start = IPv4Address(block['startAddress']['$'])
            self.end = IPv4Address(block['endAddress']['$'])
            self.network = IPv4Address('%s/%s' % (self.start.address, self.mask))
        elif reverse.address_format == IPv6Address:
            self.start = IPv6Address(block['startAddress']['$'])
            self.end = IPv6Address(block['endAddress']['$'])
            self.network = IPvAddress('%s/%s' % (self.start.address, self.mask))

    def __repr__(self):
        return '%s' % self.network

    def match(self, address):
        try:
            if self.network.addressInNetwork(IPv4Address(address).address):
                return self
        except ValueError:
            try:
                if self.network.addressInNetwork(IPv6Address(address).address):
                    return self
            except ValueError:
                raise WhoisError('Error matching address %s to %s' % (address, self.network))

        return None

class ARINReverseIP(list):
    """ARIN reverse query response

    List of networks parsed from ARIN reverse IP query

    """
    def __init__(self, address):
        try:
            self.address = IPv4Address(address).ipaddress
            self.address_format = IPv4Address
        except ValueError:
            try:
                self.address = IPv6Address(address).address
                self.address_format = IPv6Address
            except ValueError:
                raise WhoisError('Unsupported address: %s' % address)

    def __hash__(self):
        return sum([x.network.raw_value for x in self])

    def __repr__(self):
        return '%s ARIN response %d netblocks' % (self.address, len(self))

    def __parse_date_entry(self, value):
        try:
            return dateparser(value['$'])
        except ValueError, KeyError:
            raise WhoisError('Error parsing date from %s' % value)

    def __parse_number_entry(self, data):
        try:
            return int(data['$'])
        except KeyError:
            raise WhoisError('Error parsing number field %s' % data)

    def __parse_string_entry(self, data):
        if 'line' in data:
            try:
                data = data['line']
                if isinstance(data, list):
                    data.sort(lambda a, b: cmp(int(a['@number']), int(b['@number'])))
                    return ' '.join([l['$'] for l in data])
                else:
                    return data['$']
            except AttributeError:
                raise WhoisError('Error parsing string field %s' % data)

        else:
            try:
                return data['$']
            except TypeError:
                raise WhoisError('Error parsing string field %s' % data)
            except KeyError:
                raise WhoisError('Error parsing string field %s' % data)

    def __parse_address_entry(self, data):
        try:
            return self.address_format(data['$'])
        except ValueError, KeyError:
            raise WhoisError('Error parsing address from %s' % data)

    @property
    def name(self):
        return self._name
    @name.setter
    def name(self, value):
        self._name = self.__parse_string_entry(value)

    @property
    def handle(self):
        return self._ref
    @handle.setter
    def handle(self, value):
        self._handle = self.__parse_string_entry(value)

    @property
    def ref(self):
        return self._ref
    @ref.setter
    def ref(self, value):
        self._ref = self.__parse_string_entry(value)

    @property
    def comment(self):
        return self._comment
    @comment.setter
    def comment(self, value):
           self._comment = self.__parse_string_entry(value)

    @property
    def version(self):
        return self._version
    @version.setter
    def version(self, value):
        self._version = self.__parse_number_entry(value)

    @property
    def registered(self):
        return self._registered
    @registered.setter
    def registered(self, value):
        self._registered = self.__parse_date_entry(value)

    @property
    def updated(self):
        return self._updated
    @updated.setter
    def updated(self, value):
        self._updated = self.__parse_date_entry(value)

    def keys(self):
        return ['name', 'handle', 'ref', 'registered', 'updated', 'version', 'comment',]

    def items(self):
        return [(key, getattr(self, key)) for key in self.keys()]

    def values(self):
        return [getattr(self, key) for key in self.keys()]

    def match(self, address):
        """Check if address matches

        Return netblock if address matches any of our networks, otherwise None

        Exceptions matching netblock are silently ignored.
        """
        for netblock in self:
            try:
                if netblock.match(address):
                    return netblock
            except WhoisError:
                continue

        return None

def ARINReverseIPQuery(address, proxies={}):
    """ARIN IP Query

    Query ARIN REST API for IP allocation information details

    Returns ARINReverseIP object.

    """
    entry = ARINReverseIP(address)

    url = URL_TEMPLATE % {'address': entry.address}
    headers = {'Accept': 'application/arin.whoisrws-v1+json' }
    res = requests.get(url, headers=headers)
    if res.status_code != 200:
        raise WhoisError('Error fetching URL %s' % url)

    try:
        data = json.loads(res.content)
    except ValueError, emsg:
        raise WhoisError('Error parsing response: %s' % res.content)

    if 'net' not in data:
        logger.debug('DATA: %s' % res.content)
        raise WhoisError('Did not receive expected data: missing net section')
    net = data['net']
    assert isinstance(net, dict)

    for key in ( 'handle', 'name', 'comment', 'ref', 'version', ):
        if key in net:
            setattr(entry, key, net[key])

    for key, field in DATE_FIELD_MAP.items():
        try:
            setattr(entry, key, net[field])
        except KeyError:
            continue

    entry.append(ARINNetBlock(entry, net['netBlocks']))
    return entry

