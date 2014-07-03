"""
Common wrapper classes
"""

from systematic.classes import SortableContainer
from seine.address import IPv4Address, IPv6Address, \
                          EthernetMACAddress, FirewireLocalLinkAddress
from systematic.log import Logger, LoggerError

class NetworkError(Exception):
    pass


class NetworkAddress(SortableContainer):
    compare_fields = [ 'address' ]
    def __init__(self, family, address, options=[]):
        self.family = family
        self.address = address
        self.broadcast = None
        self.flags = {}
        self.parse_options(options)

    def parse_options(self, options):
        return

    def __repr__(self):
        return '%s' % self.address


class NetworkInterface(SortableContainer):
    compare_fields = [ 'name' ]

    def __init__(self, name):
        self.name = name
        self.media = None
        self.media_status = None
        self.media_config =  None
        self.media_state = None
        self.mtu = None
        self.ipv4_addresses = []
        self.ipv6_addresses = []
        self.flags = []
        self.options = {}
        self.nd6_options = {}
        self.configuration = {}
        self.vlan_id = None
        self.vlan_device = None
        self.vlan_options = {}

    def __repr__(self):
        return self.name

    def sort_addresses(self):
        self.ipv4_addresses.sort()
        self.ipv6_addresses.sort()

class NetworkInterfaceList(list):
    def update(self):
        return

    def sort(self):
        list.sort(self)
        for interface in self:
            interface.sort_addresses()


class Route(SortableContainer):
    compare_fields = [ 'address' ]

    def __init__(self, table, address, target, flags=None, refs=0, use=0, interface=None, expires=None):
        self.table = table
        self.address = address
        self.target = target
        self.flags = flags
        self.refs = refs
        self.use = use
        self.interface = interface
        self.expires = expires


class RoutingTable(object):
    def __init__(self):
        self.ipv4 = []
        self.ipv6 = []


class ARPTableEntry(SortableContainer):
    compare_fields = [ 'address' ]

    def __init__(self, address, ethernet, interface, expires=None, ifscope=None):
        self.address = IPv4Address(address)
        try:
            self.ethernet = EthernetMACAddress(ethernet)
        except ValueError:
            self.ethernet = None
        self.interface = interface
        self.expires = expires
        self.ifscope = ifscope.strip('[]')

    def __repr__(self):
        return '%s %s' % (self.address, self.ethernet)


class ARPTable(list):
    pass

