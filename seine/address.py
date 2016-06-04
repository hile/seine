"""
Classes to represent Ethernet, IPv4, IPv6 addresses and address ranges
"""

import struct
import string

from systematic.classes import SortableContainer

# Maximum value available with 32 bits
UINT_MAX = 2**32-1
U128_MAX = 2**128-1

ADDRESS_CLASS_DEFAULT = 'normal'

IPV4_ADDRESS_CLASS_MAP = {
    'this_broadcast': {
        'networks': ['0.0.0.0/8 '],
        'description': 'Used for broadcast messages to the current ("this") network as specified by RFC 1700, page 4.',
    },
    'carriernat':           {
        'networks': ['100.64.0.0/10'],
        'description': 'Used for communications between a service provider and its subscribers when using a ' +
                       ' Carrier-grade NAT, as specified by RFC 6598',
    },

    'loopback':             {
        'networks': ['127.0.0.0/8'],
        'description': 'Used for loopback addresses to the local host, as specified by RFC 990',
    },
    'link-local':           {
        'networks': ['169.254.0.0/16'],
        'description': 'Used for link-local addresses between two hosts on a single link when no IP address is ' +
                       'otherwise specified, such as would have normally been retrieved from a DHCP server, as ' +
                       'specified by RFC 3927',
    },
    'spar':                 {
        'networks': ['192.0.0.0/24'],
        'description': 'Used for the IANA IPv4 Special Purpose Address Registry as specified by RFC 5736',
    },
    'testnet':              {
        'networks': ['192.0.2.0/24'],
        'description': 'Assigned as "TEST-NET" in RFC 5737 for use solely in documentation and example source ' +
                       'code and should not be used publicly',
    },
    '6to4anycast':          {
        'networks': ['192.88.99.0/24'],
        'description': 'Used by 6to4 anycast relays as specified by RFC 3068',
    },
    'test_inter_network':     {
        'networks': ['198.18.0.0/15'],
        'description': 'Used for testing of inter-network communications between two separate subnets ' +
                       'as specified in RFC 2544',
    },
    'testnet_2':            {
        'networks': ['198.51.100.0/24'],
        'description': 'Used for testing of inter-network communications between two separate subnets ' +
                       'as specified in RFC 2544',
    },
    'testnet_3':            {
        'networks': ['203.0.113.0/24'],
        'description': 'Assigned as "TEST-NET-3" in RFC 5737 for use solely in documentation and example ' +
                       'source code and should not be used publicly.',
    },
    'rfc1918':              {
        'networks': ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
        'description': 'Used for local communications within a private network as specified by RFC 1918',
    },
    'multicast':            {
        'networks': ['224.0.0.0/4'],
        'description': 'Reserved for multicast assignments as specified in RFC 5771. 233.252.0.0/24 is ' +
                       'assigned as "MCAST-TEST-NET" for use solely in documentation and example source code.',
    },
    'reserved':             {
        'networks': ['240.0.0.0/4'],
        'description': 'Reserved for future use, as specified by RFC 6890',
    },
    'limited_broadcast':    {
        'networks': ['255.255.255.255/32'],
        'description': 'Reserved for the "limited broadcast" destination address, as specified by RFC 6890',
    },
}
IPV6_ADDRESS_CLASS_MAP = {
    'undefined':                {
        'networks': ['::/128'],
        'description': 'Unspecified address',
    },
    'loopback':                 {
        'networks': ['::1/128'],
        'description': 'loopback address to the local host',
    },
    'local_ipv4_translation':   {
        'networks': ['::ffff:0:0/96'],
        'description': 'IPv4 mapped addresses',
    },
    'discard_prefix_rfc6666':   {
        'networks': ['100::/64'],
        'description': 'Discard Prefix RFC 6666',
    },
    'global_ipv4_translation':  {
        'networks': ['64:ff9b::/96'],
        'description': 'IPv4/IPv6 translation RFC 6052',
    },
    'teredo':                   {
        'networks': ['2001::/32'],
        'description': 'Teredo tunneling',
    },
    'orchid_deprecated':        {
        'networks': ['2001:10::/28'],
        'description': 'Deprecated (previously ORCHID)',
    },
    'orchid_v2':                {
        'networks': ['2001:20::/28'],
        'description': 'ORCHIDv2',
    },
    'documentation':            {
        'networks': ['2001:db8::/32'],
        'description': 'Addresses used in documentation',
    },
    '6to4':                     {
        'networks': ['2002::/16'],
        'description': '6to4 tunneling',
    },
    'unique_local':             {
        'networks': ['fc00::/7'],
        'description': 'Unique local address',
    },
    'link_local':               {
        'networks': ['fe80::/10'],
        'description': 'Link-local address',
    },
    'multicast':                {
        'networks': ['ff00::/8'],
        'description': 'Multicast',
    },
}

IPV6_IPV4_TRANSLATION_PREFIXES = (
    '::ffff',
    '64:ff9b',
)

try:
    type(bin)
except NameError:
    def bin(str,pad32bits=True):
        if type(str) not in [int,long]:
            str = long(str)
        t={
            '0':'000','1':'001','2':'010','3':'011',
            '4':'100','5':'101','6':'110','7':'111'
        }
        s=''
        for c in oct(str).rstrip('L')[1:]:
            s+=t[c]
        s = s.lstrip('0')
        if pad32bits and len(s) < 32:
            s = '0'*(32-len(s)) + s
        return s


def isEthernetMACAddress(value):
    try:
        EthernetMACAddress(value)
    except ValueError:
        return False
    return True


class MediaAddressType(SortableContainer):
    """MAC address types base class

    Common base class for MAC address types, like Ethernet, Firewire etc.

    """
    def __init__(self, addresstype, address):
        self.type = addresstype
        self.__parseaddress__(address)

    def __parseaddress__(self, value):
        raise NotImplementedError('__parseaddress__ must be implemented in child class')

    def __repr__(self):
        return self.address

    def __hash__(self):
        return self.value

    def __int__(self):
        return self.value

    def __long__(self):
        return self.value

    def __cmp__(self, other):
        if self.__class__ == other.__class__:
            return cmp(self.value, other.value)

        elif isinstance(other, MediaAddressType):
            raise ValueError('Error comparing {0} to {1}'.format(
                    self.__class__.__name__,
                    other.__class__.__name__,
                ))

        else:
            try:
                other = self.__class__(other)
                return cmp(self.value, other.value)

            except ValueError:
                raise ValueError('Compared value is not valid {0} value: {1}'.format(
                    self.__class__.__name__,
                    other
                ))


class EthernetMACAddress(MediaAddressType):
    def __init__(self, address):
        MediaAddressType.__init__(self, 'ethernet', address)

    def __parseaddress__(self, value):
        try:
            if len(value) == 12:
                parts = [int(x, 16) for x in
                    [value[i:i+2] for i in range(0, len(value), 2)]
                ]

            elif len(value) == 6:
                parts = struct.unpack('BBBBBB', str(value))

            else:
                parts = [int(x, 16) for x in value.split(':', 5)]

            if len(parts) != 6:
                raise ValueError

            for p in parts:
                if p < 0 or p > 255:
                    raise ValueError

        except ValueError:
            raise ValueError('Not a Ethernet MAC address: {0}'.format(value))

        self.address = ':'.join(['%02x' % p for p in parts])
        self.value = sum([parts[-(len(parts)-i)]<<8*(len(parts)-i-1) for i in range(len(parts))])

class FirewireLocalLinkAddress(MediaAddressType):
    def __init__(self, address):
        MediaAddressType.__init__(self, 'firewire', address)

    def __parseaddress__(self, value):
        try:
            if len(value) == 16:
                parts = [int(x, 16) for x in
                    [value[i:i+2] for i in range(0, len(value), 2)]
                ]

            elif len(value) == 8:
                parts = struct.unpack('BBBBBBBB', str(value))

            else:
                parts = [int(x, 16) for x in value.split(':', 7)]

            if len(parts) != 8:
                raise ValueError

            for p in parts:
                if p < 0 or p > 255:
                    raise ValueError

        except ValueError:
            raise ValueError('Not a Firewire local link address: {0}'.format(value))

        self.address = ':'.join(['%02x' % p for p in parts])
        self.value = sum([parts[-(len(parts)-i)]<<8*(len(parts)-i-1) for i in range(len(parts))])


class IPv4Address(object):
    """
    Verify and format IPv4 address given in n.n.n.n/32 format,
    calculate various values for the address.

    Raises ValueError if address is not valid.

    Attributes available:
    ipaddress: x.x.x.x address
    bitmask:   bitmask (0-32)
    netmask:   netmask in x.x.x.x format
    inverted_netmask: netmask in x.x.x.x, inverted (cisco style)
    network:   network address, raises ValueError for /32 addresses
    broadcast: broadcast address, raises ValueError for /32 addresses
    first:     return first host address in network
    last:      return last host address in network

    Internally available:
    address:   IPv4 address as long integer
    mask:      IPv4 netmask as long integer
    """

    def __init__(self, address, netmask=None, oldformat=False):
        """
        Parameters:
        address: dot format address as in inet, or long integer
        netmask: netmask in dot format or long integer
        oldformat: parse 127 as 127.0.0.0 not 0.0.0.127 (as in netstat output)
        """
        self.oldformat = oldformat
        if type(address) != int and len(address) == 4 and not address.translate(None, string.digits+'abcdef'):
            address = '.'.join(str(x) for x in struct.unpack('BBBB', str(address)))
            mask = 32

        elif isinstance(address, basestring) and address[:2] == '0x':
            address = long(address, 16)
            mask = 32

        if type(address) in [int,long]:
            ip = address
            mask = 32

        else:
            try:
                (ip,mask) = address.split('/', 1)
            except ValueError:
                ip = address.strip()
                mask = 32

        if netmask:
            try:
                netmask = self.__parseaddress__(netmask)
                if netmask == UINT_MAX:
                    mask = 32
                else:
                    if bin(UINT_MAX &~ netmask)[2:].count('0')>0:
                        raise ValueError
                    mask = 32 - len(bin(UINT_MAX &~ netmask)) + 2

            except ValueError:
                raise ValueError('Invalid netmask value: {0}'.format(netmask))

        elif self.oldformat:
            if address.count('.') == 2:
                mask = 24
            elif address.count('.') == 1:
                mask = 16
            elif address.count('.') == 0:
                mask = 8
            else:
                mask = 32

        try:
            mask = int(mask)
            if mask not in range(0,33):
                raise ValueError
            self.mask = UINT_MAX ^ (2**(32-mask)-1)
        except ValueError:
            raise ValueError('Invalid netmask: {0}'.format(mask))

        try:
            self.raw_value = self.__parseaddress__(ip)
        except ValueError:
            if isinstance(address,basestring) and address=='default':
                self.raw_value = self.__parseaddress__('0.0.0.0')
                self.mask = 0
            else:
                raise ValueError('Invalid address: {0}'.format(address))

    def __parsenumber__(self, value):
        """
        Parses decimal, octal, hex value from string
        """
        value = str(value)
        if value[:2] == '0x':
            if not value[2:].translate(None, string.digits):
                return int(value, 16)

        elif value[:1] == '0':
            if not value.translate(None, string.digits):
                return int(value, 8)

        else:
            return int(value)

        raise ValueError('Invalid number {0}'.format(value))

    def __parseaddress__(self, value):
        """
        Try to parse an ip-address from various crazy formats defined
        for IP addresses. Of course, sane people would only pass normal
        addresses to us but who knows...
        """
        value = str(value)

        if value.count('.') == 3:
            dotted = []
            parts = value.split('.')
            for i,p in enumerate(parts):
                p = self.__parsenumber__(p)
                if p not in range(0, 256):
                    raise ValueError
                dotted.append(p)

            return reduce(lambda x,y:x+y,[
                (dotted[0]<<24), (dotted[1]<<16), (dotted[2]<<8), (dotted[3]),
            ])

        elif value.count('.') == 2:
            dotted = []
            parts = value.split('.')
            for i,p in enumerate(parts):
                p = self.__parsenumber__(p)
                if not self.oldformat:
                    if i>2 and (p<0 or p>2**8):
                        raise ValueError
                    elif i==2 and (p<0 or p>2**16):
                        raise ValueError
                else:
                    if p<0 or p>2**8:
                        raise ValueError
                dotted.append(p)
            if not self.oldformat:
                return reduce(lambda x,y:x+y,[
                    (dotted[0]<<24), (dotted[1]<<16), (dotted[2])
                ])
            else:
                return reduce(lambda x,y:x+y,[
                    (dotted[0]<<24), (dotted[1]<<16), (dotted[2]<<8)
                ])

        elif value.count('.') == 1:
            dotted = []
            parts = value.split('.')
            for i,p in enumerate(parts):
                p = self.__parsenumber__(p)
                if not self.oldformat:
                    if i==0 and (p<0 or p>2**8):
                        raise ValueError
                    elif i==1 and (p<0 or p>2**24):
                        raise ValueError
                else:
                    if (p<0 or p>2**8):
                        raise ValueError
                dotted.append(p)
            if not self.oldformat:
                return reduce(lambda x,y: x+y, [(dotted[0]<<24), (dotted[1])])
            else:
                return reduce(lambda x,y: x+y, [(dotted[0]<<24), (dotted[1]<<16)])

        elif value.count(' ') == 3:
            # Try 'aa bb cc dd' format hex address conversion. Silly? Yes
            dotted = []
            try:
                dotted = [int(x.strip(), 16) for x in value.split(' ')]
                return reduce(lambda x,y:x+y,[
                    (dotted[0]<<24), (dotted[1]<<16), (dotted[2]<<8), (dotted[3]),
                ])
            except ValueError:
                pass

        else:
            if not self.oldformat:
                return self.__parsenumber__(value)
            else:
                return self.__parsenumber__(value) << 24

        raise ValueError

    def __repr__(self):
        return self.ipaddress

    def __str__(self):
        """
        Returns a CIDR address formatted string for this address
        """
        return self.cidr_address

    def __len__(self):
        """
        Return number of hosts possible in the network, excluding network
        address and broadcast address: NOT reserving a gateway address!
        """
        if self.bitmask > 30:
            return 1
        elif self.bitmask == 30:
            return 2

        first = (self.raw_value & self.mask) + 1
        last  = (self.raw_value & self.mask) + (UINT_MAX &~ self.mask)
        return last-first

    def __hash__(self):
        return long(self.raw_value)

    def __cmp__(self, other):
        if isinstance(other, basestring):
            other = IPv4Address(other)
            return cmp(self.raw_value, other.raw_value)

        elif hasattr(other, 'raw_value'):
            return cmp(self.raw_value, other.raw_value)

        elif isinstance(other, int):
            return cmp(self.raw_value, other)

        else:
            raise ValueError("Can't compare IPv4Address to {0}".format(type(other)))

    def __eq__(self, other):
        return self.__cmp__(other) == 0

    def __ne__(self, other):
        return self.__cmp__(other) != 0

    def __lt__(self, other):
        return self.__cmp__(other) < 0

    def __lte__(self, other):
        return self.__cmp__(other) <= 0

    def __gt__(self, other):
        return self.__cmp__(other) > 0

    def __gte__(self, other):
        return self.__cmp__(other) >= 0

    def __long__(self):
        """
        Return the integer representation for this IPv4 address
        """
        return self.raw_value

    def __long2address__(self, value):
        """
        Convert a long integer back to n.n.n.n format
        """
        parts = []
        for i in range(0, 4):
            p = str((value &~ (UINT_MAX^2**(32-i*8)-1)) >> (32-(i+1)*8))
            parts.append(p)

        return '.'.join(parts)

    def __addressclass__(self):
        for aclass, details in IPV4_ADDRESS_CLASS_MAP.items():
            for net in details['networks']:
                if IPv4Address(net).addressInNetwork(self.ipaddress):
                    return aclass

        return ADDRESS_CLASS_DEFAULT

    @property
    def address(self):
        return self.__long2address__(self.raw_value)

    @property
    def ipaddress(self):
        return self.__long2address__(self.raw_value)

    @property
    def cidr_address(self):
        if self.bitmask==32:
            return '{0}'.format(self.ipaddress)
        else:
            return '{0}/{1}'.format(self.ipaddress, self.bitmask)

    @property
    def bitstring(self):
        return '0x{0}'.format(''.join(self.hexbytes))

    @property
    def hexbytes(self):
        return map(lambda x:
            '%02x' % int(x),
            self.__long2address__(self.raw_value).split('.')
        )

    @property
    def addressclass(self):
        return self.__addressclass__()

    @property
    def bitmask(self):
        if self.mask == UINT_MAX:
            return 32
        return 32-len(bin(UINT_MAX &~ self.mask))+2

    @property
    def netmask(self):
        return self.__long2address__(self.mask)

    @property
    def inverted_netmask(self):
        return self.__long2address__(UINT_MAX ^ self.mask)

    @property
    def network(self):
        if self.bitmask == 32:
            self.ipaddress
        return self.__long2address__(self.raw_value & self.mask)

    @property
    def broadcast(self):
        if self.bitmask == 32:
            raise ValueError('No broadcast address for /32 address')
        return self.__long2address__(
            (self.raw_value & self.mask) + (UINT_MAX &~ self.mask)
        )

    @property
    def first(self):
        if self.bitmask == 32:
            return self.ipaddress
        if self.bitmask == 31:
            return self.__long2address__(
                self.raw_value & self.mask,
                netmask=self.netmask,
            )
        return IPv4Address(
            (self.raw_value & self.mask) + 1,
            netmask=self.netmask
        )

    @property
    def last(self):
        if self.bitmask == 32:
            return self.ipaddress
        if self.bitmask == 31:
            return self.__long2address__((self.raw_value & self.mask)+1)
        return IPv4Address(
            (self.raw_value & self.mask) + (UINT_MAX &~ self.mask) - 1,
            netmask=self.netmask
        )

    @property
    def next(self):
        address = self.raw_value+1
        if address >= UINT_MAX:
            return None
        return IPv4Address(address, netmask=self.netmask)

    @property
    def prev(self):
        address = self.raw_value-1
        if address < 0:
            return None
        return IPv4Address(address, netmask=self.netmask)

    @property
    def next_network(self):
        address = self.raw_value+2**(32-self.bitmask)
        if address >= UINT_MAX:
            return None
        return IPv4Address('{0}/{1}'.format(address, self.bitmask))

    @property
    def previous_network(self):
        address = self.raw_value-2**(32-self.bitmask)
        if address < 0:
            return None
        return IPv4Address('{0}/{1}'.format(address, self.bitmask))

    @property
    def dns_reverse_ptr(self):
        return '{0}.in-addr.arpa.'.format('.'.join(reversed(self.ipaddress.split('.'))))

    @property
    def dns_reverse_origin(self):
        if self.bitmask >= 24:
            return '{0}.in-addr.arpa.'.format('.'.join(reversed(self.ipaddress.split('.')[:3])))
        elif self.bitmask >= 16:
            return '{0}.in-addr.arpa.'.format('.'.join(reversed(self.ipaddress.split('.')[:2])))
        elif self.bitmask >= 8:
            return '{0}.in-addr.arpa.'.format(self.ipaddress.split('.')[0])
        else:
            raise ValueError("Can't create reverse origin for mask {0}".format(self.bitmask))

    def __getitem__(self, item):
        try:
            return getattr(self, item)
        except TypeError:
            raise KeyError
        except AttributeError, e:
            raise KeyError('No such IPv4Address item: {0}'.format(item))

    def addressInNetwork(self, ip):
        """
        Tests if given IPv4 address is in range of this network,
        including network and broadcast addresses
        """
        if type(ip) != IPv4Address:
            ip = IPv4Address(ip)
        if self.bitmask == 0:
            return True

        if self.bitmask == 32 and ip.raw_value != self.raw_value:
            return False
        else:
            first = self.raw_value & self.mask
            last = (self.raw_value & self.mask) + (UINT_MAX &~ self.mask)
            if ip.raw_value < first or ip.raw_value > last:
                return False

        return True

    def hostInNetwork(self, address):
        """
        Tests if given IPv4 address is in range of this network,
        excluding network and broadcast addresses
        """
        ip = IPv4Address(address)
        if self.bitmask == 0:
            return True
        if self.bitmask == 32 and ip.raw_value != self.raw_value:
            return False

        if self.bitmask == 31:
            first = self.raw_value & self.mask
            if ip.raw_value < first or ip.raw_value > first+1:
                return False
        else:
            first = self.raw_value & self.mask
            last = (self.raw_value & self.mask) + (UINT_MAX &~ self.mask)
            if ip.raw_value <= first or ip.raw_value >= last:
                return False

        return True

    def split(self, bitmask, maxcount=None):
        if self.bitmask >= 30:
            raise ValueError("Can't split network with mask {0}".format(self.bitmask))

        try:
            bitmask = int(bitmask)
            if bitmask < 1 or bitmask > 30:
                raise ValueError
        except ValueError:
            raise ValueError('Invalid split mask: {0}'.format(bitmask))

        if bitmask <= self.bitmask:
            raise ValueError('Split mask must be larger than network mask {0}'.format(self.bitmask))

        last = self.last

        networks = [IPv4Address('{0}/{1}'.format((self.ipaddress, bitmask)))]
        next = IPv4Address('{0}/{1}'.format((self.raw_value+2**(32-bitmask), bitmask)))
        while True:
            if maxcount is not None and maxcount < len(networks):
                break
            networks.append(next)

            if next.last.raw_value >= last.raw_value:
                break
            next = IPv4Address('{0}/{1}'.format((next.raw_value + 2**(32-bitmask), bitmask)))

        return networks

class IPv4AddressRangeList(list):
    """
    Parses nmap style address range specifications to IPv4AddressRange
    objects. Supported example lines:
        10.0.0.1-254
        10.0.1,2,3.1-254
        10,11.0.1,2,3-5.1-254
    """

    def __init__(self, value):
        try:
            (parts) = value.split('.', 3)
        except ValueError:
            raise ValueError('Unsupported value: {0}'.format(value))

        part_lists = []
        for i, field in enumerate(parts[:-1]):
            part_lists.append([])
            if field.count(',')>0:
                values = field.split(',')
            else:
                values = [field]

            for v in values:
                if v.count('-')==1:
                    start, end = [int(x) for x in v.split('-')]
                    if (start>end): raise ValueError
                    for j in range(start, end+1):
                        part_lists[i].append(j)
                else:
                    part_lists[i].append(v)

        part_lists.append(parts[-1].split(','))
        for p1 in [str(x) for x in part_lists[0]]:
            for p2 in [str(x) for x in part_lists[1]]:
                for p3 in [str(x) for x in part_lists[2]]:
                    for p4 in [str(x) for x in part_lists[3]]:
                        self.append(IPv4AddressRange('.'.join([p1, p2, p3, p4])))

class IPv4AddressRange(object):
    """
    Defines a IPv4 address range, which you can:
    - check length of arbitrary range quickly
    - check if given address is in range
    - iterate to get IPv4Address objects for each address in range
    """

    def __init__(self, first, last=None):
        """
        First address and last address must be valid IPv4 addresses, and first
        address must be smaller than last address.

        If last is omitted and only first address is given, the value must be a
        valid subnet and the generated range covers all addresses, not just 'hosts':
        i.e. 192.168.0.0/24 == 192.168.0.0-192.168.0.255

        Any netmask given to the first or last address is ignored, i.e.
        IPv4AddressRange('192.168.0.0/24','192.168.0.10/8') returns range
        192.168.0.0-192.168.0.10

        Raises ValueError if the addresses can not be parsed or if the range is
        invalid.
        """
        self.__next = 0

        if isinstance(first, IPv4Address) and isinstance(last, IPv4Address):
            self.first = first
            self.last = last

        elif last is not None:
            self.first = IPv4Address(first)
            self.last = IPv4Address(last)

        elif first.count('/') == 1:
            # Support giving a subnet as range, but
            try:
                network = IPv4Address(first)
                self.first = IPv4Address(network.network)
                self.last = IPv4Address(network.broadcast)
            except ValueError:
                raise ValueError('Error parsing {0}: {1}'.format(first,e))

        else:
            # Support nmap format like 1.2.3.1-254 for 1.2.3.1 to 1.2.3.254
            try:
                (start_ip,subnet_last) = first.split('-', 1)
                (start_ip, subnet_last) = first.split('-', 1)
                self.first = IPv4Address(start_ip)
                last = '{0}.{1}'.format(
                    '.'.join(self.first.ipaddress.split('.')[:-len(subnet_last.split('.'))]),
                    subnet_last
                )
                self.last = IPv4Address(last.lstrip('.'))
            except ValueError, emsg:
                raise ValueError('Error parsing {0}: {1}'.format(first, emsg))

        if self.last < self.first:
            raise ValueError('Invalid range: last address is smaller than first address')

    def __repr__(self):
        return '{0}-{1}'.format(self.first.ipaddress, self.last.ipaddress)

    def __str__(self):
        return '{0}-{1}'.format(self.first.ipaddress, self.last.ipaddress)

    def __len__(self):
        """
        Returns number of addresses in the range, including first and last address
        """
        return self.last.address - self.first.address + 1

    def __iter__(self):
        return self

    def next(self):
        if self.first.raw_value + self.__next > self.last.raw_value:
            raise StopIteration

        address = IPv4Address(self.first.raw_value + self.__next)
        self.__next += 1

        return address

    def contains(self, item):
        """
        Check if given address is in the range, including first and last
        address.

        The item must be IPv4Address object.
        """
        if item.address < self.first.address or item.address > self.last.address:
            return False
        return True

class IPv6Address(dict):
    """IPv6 address

    """
    def __init__(self, value):

        if value == 'default':
            value = '::0/0'

        try:
            address, bitmask = value.split('/')
        except ValueError:
            address = value
            bitmask = 128

        try:
            bitmask = int(bitmask)
            if int(bitmask) < 0 or int(bitmask) > 128:
                raise ValueError

        except ValueError:
            raise ValueError('Invalid IPv6 mask {0}'.format(value))

        subs = address.split(':')
        try:
            split = subs.index('')
            prefix = subs[:split]
            suffix = subs[split + 1:]
            subs = prefix + ['0'] * (8 - len(prefix) - len(suffix)) + suffix
            subs =  map(lambda x: x != '' and int(x, 16) or 0, subs)
        except ValueError:
            subs = [int(v, 16) for v in subs]

        if len(subs) != 8:
            raise ValueError('Invalid IPv6 address {0}'.format(value))

        bitstring = '{0}'.format(''.join('%04x' % v for v in subs))
        raw_value = long('0x{0}'.format(bitstring), 16)
        revnibbles = '.'.join(c for c in '{0:032x}'.format(raw_value)[::-1])

        network_value = raw_value &~ ( U128_MAX & (2**(128-bitmask) - 1) )
        network_string = '%032x' % network_value
        if bitmask < 96:
            network_subs = [sub for sub in subs[:((128 - bitmask) / 16)]]
            if network_subs.count(0) != len(network_subs):
                if network_subs:
                    while network_subs[-1] == 0:
                        network_subs.pop()
                network = '{0}::/{1}'.format(':'.join('%x' % int(network_string[i:i+4], 16) for i in range(0, len(network_subs) * 4, 4)), bitmask)
            else:
                network = '::/{0}'.format(bitmask)
            network_bitstring = '0x{0:032x}'.format(network_value)
        elif bitmask < 128:
            network = '::{0}/{1}'.format(network_string, bitmask)
            network_bitstring = '0x{0:032x}'.format(network_value)
        else:
            network = None
            network_bitstring = None

        self.update({
            'type': address.endswith('::') and 'subnet' or 'address',
            'address':  address,
            'bitmask': bitmask,
            'bitstring': '0x{0:032x}'.format(raw_value),
            'network_bitstring': network_bitstring,
            'network': network,
            'revnibbles_int': '{0}.ip6.int.'.format(revnibbles),
            'revnibbles_arpa': '{0}.ip6.arpa.'.format(revnibbles),
        })


    @property
    def address(self):
        return self['address'].lower()

    @property
    def addressclass(self):
        for aclass, details in IPV6_ADDRESS_CLASS_MAP.items():
            for net in details['networks']:
                if IPv6Address(net).addressInNetwork(self.address):
                    return aclass

        return ADDRESS_CLASS_DEFAULT

    @property
    def bitstring(self):
        return self['bitstring']

    @property
    def bitmask(self):
        return self['bitmask']

    @property
    def network(self):
        return self['network']

    @property
    def network_bitstring(self):
        return self['network_bitstring']

    @property
    def revnibbles_arpa(self):
        return self['revnibbles_arpa']

    @property
    def revnibbles_int(self):
        return self['revnibbles_int']

    def __getattr__(self, attr):
        try:
            return self[attr]
        except KeyError:
            raise AttributeError('No such IPv6Address attribute: {0}'.format(attr))

    def __hash__(self):
        return long(self.address)

    def __cmp__(self, other):
        if not hasattr(other, 'address'):
            return -1

        if self.address < other.address:
            return -1

        elif self.address > other.address:
            return 1

        return 0

    def __eq__(self,other):
        return self.__cmp__(other) == 0

    def __ne__(self,other):
        return self.__cmp__(other) != 0

    def __lt__(self, other):
        return self.__cmp__(other) < 0

    def __lte__(self, other):
        return self.__cmp__(other) <= 0

    def __gt__(self, other):
        return self.__cmp__(other) > 0

    def __gte__(self, other):
        return self.__cmp__(other) >= 0

    def __repr__(self):
        return '{0}/{1}'.format(self.address, self.bitmask)

    def __addrfmt__(self, address, mask):
        s = '%032x' % address
        value = ['%x' % int(s[i:i+4], 16) for i in range(0,32,4)]

        # Find the longest chain of 0's to truncate
        longest = 0
        index = None
        i = 0
        while i < len(value):
            if int(value[i],16) != 0:
                i+=1
                continue
            zeros = 0
            for v in value[i:]:
                if int(v,16) != 0:
                    break
                zeros += 1
            if zeros > longest:
                longest = zeros
                index = i
            i += zeros

        if index is not None:
            del(value[index:index+longest])
            value.insert(index,'')

        value = ':'.join(value)
        if value.startswith(':'):
            value = ':'+value
        if value.endswith(':'):
            value += ':'

        return '{0}/{1}'.format(value, mask)

    @property
    def first(self):
        return IPv6Address(
            self.__addrfmt__(
                int(self.network_bitstring,16)+1,
                self.bitmask
            )
        )

    @property
    def last(self):
        return IPv6Address(
            self.__addrfmt__(
                int(self.network_bitstring,16)+2**(128-self.bitmask)-1,
                self.bitmask
            )
        )

    @property
    def next(self):
        next = int(self.bitstring,16) + 1
        if next > U128_MAX:
            return None
        return IPv6Address(self.__addrfmt__(next,self.bitmask))

    @property
    def previous(self):
        next = int(self.bitstring,16) - 1
        if next < 0:
            return None
        return IPv6Address(self.__addrfmt__(next,self.bitmask))

    @property
    def next_network(self):
        network = int(self.network_bitstring,16) + 2**(128-self.bitmask)
        if network >= U128_MAX:
            return None
        return IPv6Address(self.__addrfmt__(network,self.bitmask))

    @property
    def previous_network(self):
        network = int(self.network_bitstring,16) - 2**(128-self.bitmask)
        if network < 0:
            return None
        return IPv6Address(self.__addrfmt__(network,self.bitmask))

    def addressInNetwork(self,value):
        """
        Tests if given IPv6 address is in range of this network,
        including network and broadcast addresses
        """
        if type(value) is not IPv6Address:
            try:
                value = IPv6Address(value)
            except ValueError,e:
                raise ValueError('Invalid IPv6Address: {0}'.format(value))

        value = int(value.bitstring,16)
        first = int(self.network_bitstring,16)
        last = int(self.network_bitstring,16)+2**(128-self.bitmask)-1
        if value < first or value > last:
            return False

        return True

    def hostInNetwork(self, address):
        if type(address) is not IPv6Address:
            try:
                address = IPv6Address(address)
            except ValueError,e:
                raise ValueError('Invalid IPv6Address: {0}'.format(address))

        address = int(address.bitstring, 16)
        first = int(self.network_bitstring, 16) + 1
        last = int(self.network_bitstring, 16) + 2**(128-self.bitmask) - 1
        if address < first or address > last:
            return False

        return True

class IPv4AddressList(dict):
    def __init__(self,values):
        for v in values:
            if not isinstance(v,IPv4Address):
                v = IPv4Address(v)

            if self.has_key(v.address):
                print 'Duplicate address'
                continue

            self[v.address] = v

    def keys(self):
        return sorted(map(lambda a: int(a), dict.keys(self)))

    def values(self):
        return [self[a] for a in map(lambda a: int(a), self.keys())]

    def items(self):
        return [(a,self[a]) for a in map(lambda a: int(a), self.keys())]

    def sorted_shortened(self):
        """
        Return the entries in IPv4Address, sorted by address and compressed
        to IPv4Range objects when consequetive addresses are found.

        Returns mixed list of IPv4Address and IPv4Range objects.
        """
        addresses = []
        iprange = []
        for v in self.values():
            if iprange == []:
                iprange = [v]
                continue

            if v.address == iprange[-1].address+1:
                iprange.append(v)
                continue

            if len(iprange) > 1:
                addresses.append(IPv4AddressRange(
                    iprange[0].ipaddress,
                    iprange[-1].ipaddress,
                ))
            elif len(iprange) == 1:
                addresses.append(iprange[0])
            else:
                raise NotImplementedError('IMPOSSIBLE BUG: {0}'.format(iprange))

            iprange = [v]

        if len(iprange) > 1:
            addresses.append(IPv4AddressRange(iprange[0].ipaddress, iprange[-1].ipaddress))

        elif len(iprange) == 1:
            addresses.append(iprange[0])

        return addresses

class SubnetPrefixIterator(object):
    def __init__(self, address, splitmask):
        try:
            splitmask = int(splitmask)
        except ValueError:
            raise ValueError('Invalid splitmask')

        try:
            self.address = IPv4Address(address)
            self.last = self.address.bitmask <= 29 and self.address.last.address or None
        except ValueError,emsg:
            try:
                self.address = IPv6Address(address)
                self.last = long(self.address.last.bitstring, 16)
            except ValueError:
                raise ValueError('Not valid IPv4 or IPv6 address: {0}'.format(address))

        if isinstance(self.address,IPv4Address) and self.address.bitmask>=30:
            raise ValueError("Can't split address with mask {0}".format(self.address.bitmask))
        if self.address.bitmask >= splitmask:
            raise ValueError('Split mask must be smaller than network mask')

        if isinstance(self.address, IPv4Address):
            self.first = IPv4Address('{0}/{1}'.format(self.address.network, splitmask))
        if isinstance(self.address,IPv6Address):
            self.first = IPv6Address('{0}/{1}'.format(self.address.network.split('/')[0], splitmask))
        self.__next = self.first

    def __iter__(self):
        return self

    def next(self):
        try:
            if type(self.__next) == IPv4Address:
                if self.__next is None:
                    raise StopIteration
                entry = self.__next
                if self.address.last.raw_value <= entry.first.raw_value:
                    raise StopIteration
                self.__next = entry.next_network

            if type(self.__next) == IPv6Address:
                if self.__next is None:
                    raise StopIteration
                entry = self.__next
                entry_first = long(entry.first.bitstring, 16)
                if self.last <= entry_first:
                    raise StopIteration
                self.__next = entry.next_network

        except StopIteration:
            self.__next = self.first
            raise StopIteration

        return entry

def parse_address(value):
    """Parse address

    Parse address to IPv4Address, IPv6Address or EthernetMACAddress

    """
    for fmt in (IPv4Address, IPv6Address, EthernetMACAddress):
        try:
            return fmt(value)
        except ValueError:
            pass

    raise ValueError('Unknown address format: {0}'.format(value))
