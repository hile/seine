"""
Utility classes for network routing
"""

from seine.address import IPv4Address, IPv6Address, EthernetMACAddress
from subprocess import check_output, CalledProcessError

class RoutingTableError(Exception):
    pass

class IPRoutingTable(object):
    def __init__(self):
        self.ipv4 = []
        self.ipv6 = []

        try:
            output = check_output(['netstat', '-rn'])
        except CalledProcessError, emsg:
            raise RoutingTableError('Error checking netstat -rn output: %s' % emsg)

        for l in [x.strip() for x in output.split('\n') if x!='']:

            fields = l.split()
            if fields[0] == 'default':
                address = 'default'
            else:
                address = self.__parse_address__(fields[0])
                if address is None:
                    continue

            gateway = self.__parse_address__(fields[1])
            if gateway is not None:
                gateway_type = 'route'
            else:
                if fields[1][:4]=='link':
                    gateway = fields[1][4:].strip('#')
                    gateway_type = 'link'
                else:
                    try:
                        gateway = EthernetMACAddress(fields[1])
                        gateway_type = 'host'
                    except ValueError, emsg:
                        raise RoutingTableError('Error parsing gateway %s: %s' % (fields[1], emsg))

            if isinstance(address, IPv4Address) or isinstance(gateway, IPv4Address):
                if isinstance(address, basestring) and address=='default':
                    address = IPv4Address('default')
                self.ipv4.append(IPv4Route(address, gateway, gateway_type, *fields[2:]))

            if isinstance(address, IPv6Address) or isinstance(gateway, IPv6Address):
                if isinstance(address, basestring) and address=='default':
                    address = IPv6Address('default')
                self.ipv6.append(IPv6Route(address, gateway, gateway_type, *fields[2:]))

    def __parse_address__(self, address):
        try:
            return IPv4Address(address, oldformat=True)

        except ValueError:

            try:
                (address, interface) = address.split('%')
                (interface, mask) = interface.split('/')
            except ValueError:
                interface = None
                mask = None
                pass

            try:
                if mask is not None:
                    return IPv6Address('/'.join([address, mask]))
                else:
                    return IPv6Address(address)
            except IndexError:
                pass
            except ValueError:
                pass

        return None

    def filter(self, **kwargs):
        matches = []
        for route in self.ipv4 + self.ipv6:
            nomatch = False
            for k, v in kwargs.items():

                if k=='gateway' and v=='default':

                    if getattr(route, 'gateway_type')!='route':
                        nomatch = True
                        continue

                    k = 'address'
                    if isinstance(route.address, IPv4Address):
                        v = IPv4Address('default')
                    if isinstance(route.address, IPv6Address):
                        v = IPv6Address('default')

                if not hasattr(route, k) or getattr(route, k)!=v:
                    nomatch = True

            if not nomatch:
                matches.append(route)
        return matches

    def match(self, address):
        matches = []
        for route in self.ipv4 + self.ipv6:
            if route.match(address):
                matches.append(route)
        matches.sort(lambda x, y: cmp(y.address.bitmask, x.address.bitmask))
        return matches

    def best_route(self, address):
        matches = self.match(address)
        if not matches:
            return None
        return matches[0]

class Route(object):
    def __init__(self, address, gateway, gateway_type, interface=None,
                       expire=None, flags=None, refs=None, used=None):
        self.address = address
        self.gateway = gateway
        self.gateway_type = gateway_type
        self.interface = interface
        self.expire = expire
        self.flags = flags is not None and flags or []
        self.refs = refs is not None and refs or 0
        self.used = refs is not None and refs or 0

    def match(self, address):
        if isinstance(address, basestring):
            try:
                address = type(self.address)(address)
            except ValueError:
                return False
        return self.address.addressInNetwork(address)

    @property
    def gateway_mac_address(self):
        if self.gateway_type not in ['route', 'host']:
            return None
        try:
            output = check_output(['arp', '-an'])
        except CalledProcessError, emsg:
            raise RoutingTableError('Error checking arp -rn output: %s' % emsg)
        for l in output.split('\n'):
            try:
                name, addr, at, mac, rest = l.split(None, 4)
                addr = addr.strip('()')
            except ValueError, emsg:
                continue
            if addr==self.gateway:
                return EthernetMACAddress(mac)
        return None

class IPv4Route(Route):
    def __init__(self, address, gateway, gateway_type, flags=None, refs=None,
                       used=None, interface=None, expire=None):
        if flags is not None:
            flags = list(flags)
        if refs is not None:
            refs = int(refs)
        if used is not None:
            used = int(used)
        if expire is not None:
            expire = int(expire)
        Route.__init__(self, address, gateway, gateway_type, refs=refs,
                             used=used, interface=interface, expire=expire)

    def __repr__(self):
        if self.address is None:
            return 'default via %s (%s)' % (self.gateway, self.interface)
        else:
            return '%s via %s (%s)' % (self.address, self.gateway, self.interface)

class IPv6Route(Route):
    def __init__(self, address, gateway, gateway_type,
                       flags=None, interface=None, expire=None):
        if flags is not None:
            flags = list(flags)
        if expire is not None:
            expire = int(expire)
        Route.__init__(self, address, gateway, gateway_type,
                             flags=flags, interface=interface, expire=expire)

    def __repr__(self):
        if self.address is None:
            return 'default via %s (%s)' % (self.gateway, self.interface)
        else:
            return '%s via %s (%s)' % (self.address, self.gateway, self.interface)
