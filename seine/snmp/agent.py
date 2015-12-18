"""
SNMP agent base class for net-snmp pass/pass_persist agents.

See the SNMPAgentTest class below how to use the SNMPAgent class.
"""

import sys
import os
import re
import time
import signal
import errno
import select

from systematic.shell import Script, ScriptThread, ScriptError
from systematic.log import Logger, LoggerError
from seine.address import IPv4Address
from seine.snmp import SNMPError

# Valid SNMP data types
SNMP_DATA_TYPE_MAP = {
    'integer':      lambda x: int(x),
    'gauge':        lambda x: int(x),
    'counter':      lambda x: int(x),
    'timeticks':    lambda x: int(x),
    'string':       lambda x: str(x),
    'ipaddress':    lambda x: str(IPv4Address(x)),
    'objectid':     lambda x: str(x),
}


class OIDPrefix(object):
    """Sortable OID base class

    Base class for OID prefixes, sortable in OID order

    """
    def __init__(self, oid):
        self.log = Logger('snmp').default_stream
        self.oid = self.__format_oid__(oid)
        self.oid_string = self.__format_oid_string__(oid)

        self._parent = None
        self._next = None

    def __format_oid_string__(self, oid):
        return '.%s' % '.'.join(str(x) for x in self.__format_oid__(oid))

    def __format_oid__(self, oid):
        """Format OID

        Format OID string to validated OID list

        Return list of integeres
        """

        if isinstance(oid, basestring):
            try:
                oid = oid.strip('.').split('.')
            except ValueError:
                raise ValueError('Invalid OID: %s' % oid)

        return self.__validate_oid__(oid)

    def __validate_oid__(self, oid):
        """Validate OID and return

        Validate list of integers to be a valid OID

        Returns value if OK
        """
        try:
            oid = [int(x) for x in oid]
            for x in oid:
                if x<=0:
                    raise ValueError

        except ValueError:
            raise ValueError('Invalid OID: %s' % oid)

        return oid

    def __invalid__(self, message):
        """Invalid request

        Log error and return None

        """
        self.log.debug('%s' % message)
        return None

    def __cmp__(self, other):
        """Compare oid prefix items

        Compares OID prefixes

        """
        if isinstance(other, basestring):
            oid = self.__format_oid__(other)

        elif isinstance(other, OIDPrefix):
            oid = other.oid

        else:
            raise ValueError('Error comparing OIDPrefix to %d' % type(other))

        if len(oid) != len(self.oid):
            return cmp(len(self.oid), len(oid))

        for i in range(0, len(oid)):
            if oid[i] != self.oid[i]:
                return cmp(self.oid[i], oid[i])

        return cmp(self.oid, oid)

    def __eq__(self, oid):
        return self.__cmp__(oid) == 0

    def __ne__(self, oid):
        return self.__cmp__(oid) != 0

    def __lt__(self, oid):
        return self.__cmp__(oid) < 0

    def __le__(self, oid):
        return self.__cmp__(oid) <= 0

    def __gt__(self, oid):
        return self.__cmp__(oid) > 0

    def __ge__(self, oid):
        return self.__cmp__(oid) >= 0

    @property
    def get_response(self):
        return None

    @property
    def next_response(self):
        return None

    @property
    def parent(self):
        return self._parent
    @parent.setter
    def parent(self, value):
        self._parent = value

    @property
    def next(self):
        return self._next
    @next.setter
    def next(self, value):
        self._next = value

    def match(self, other):
        """Match other OID

        Match OID prefixes. Default function checks if self.oid == other.oid

        Override in child class (for example, trees match tree prefix)
        """
        return self == other


class Item(OIDPrefix):
    def __init__(self, oid, key, value=None, readonly=True):
        super(Item, self).__init__(oid)
        self.readonly = readonly

        if key in SNMP_DATA_TYPE_MAP.keys():
            self.key = key
        else:
            raise SNMPError('Invalid item type: %s' % key)

        if value is not None:
            try:
                self.value = SNMP_DATA_TYPE_MAP[self.key](value)
            except:
                raise SNMPError('Invalid %s item value "%s"' % (self.key, value))
        else:
            self.value = None

    def __repr__(self):
        return '%s %s %s' % (self.oid_string, self.key, self.value)

    @property
    def get_response(self):
        """GET response for an item

        Strings required for formatted GET response

        """
        return '%s\n%s\n%s' % (self.oid_string, self.key, self.value)

    @property
    def next_response(self):
        """NEXT response for an item

        Strings required for formatted NEXT response

        """
        return '%s\n%s\n%s' % (self.oid_string, self.key, self.value)

    def check_length(self, value):
        """Check SET value length

        Override in child class to check SET value length

        """
        return True

    def check_value(self, value):
        """Check SET value

        Override in child class to check SET value

        """
        return True

    def check_value_consistency(self, value):
        """Check SET value consistency

        Override in child class to check SET value consistency

        """
        return True

class Tree(OIDPrefix):
    """SNMP agent OID Tree

    Tree of SNMP OIDs. Can contain items or subtrees

    """
    def __init__(self, oid):
        super(Tree, self).__init__(oid)

        self.items = []
        self.item_index = {}

        self.subtrees = []

    def __repr__(self):
        return self.oid_string

    def __register__(self, entry, index=0, next=None):
        """Register wrapper

        Method to actually register things:
        - register trees if given
        - add OID to item_index
        - link to previous item's next

        """
        entry.parent = self

        if index > 0:
            previous = self.items[index - 1]
            previous.next = entry
        else:
            previous = None
        entry.next = next

        self.items.append(entry)
        self.item_index[entry.oid_string] = entry

        if isinstance(entry, Tree):
            self.subtrees.append(entry)

        self.items.sort()
        return entry

    def clear(self):
        """Clear items

        Clear items from tree, preserve subtrees

        """
        for oid in sorted(self.item_index.keys()):
            item = self.item_index[oid]
            if isinstance(item, Item):
                del self.item_index[oid]
            elif isinstance(item, Tree):
                item.clear()

        for item in [x for x in self.items]:
            if isinstance(item, Item):
                self.items.remove(item)
            elif isinstance(item, Tree):
                item.clear()

    def relative_oid(self, oid):
        if oid == self.oid:
            raise SNMPError('Attempt to get relative oid for tree root: %s' % self.oid)

        if oid[:len(self.oid)] != self.oid:
            raise SNMPError('OID out of tree %s: %s' % (self.oidstring, oid))

        return oid[len(self.oid):]

    def match(self, other):
        """Check OID prefix match

        Check if given object matches our OID prefix
        """
        if isinstance(other, basestring):
            oid = self.__format_oid__(other)

        elif isinstance(other, list):
            oid = self.__validate_oid__(other)

        elif isinstance(other, OIDPrefix):
            oid = other.oid

        else:
            raise SNMPError('UNSUPPORTED MATCH TYPE: %s' % type(other))

        if len(oid) < len(self.oid):
            return False

        if oid[:len(self.oid)] != self.oid:
            return False

        return True

    def register_tree(self, oid):
        """Register subtree

        Register a new subtree with given OID

        Returns the created Tree object
        """
        return self.add(Tree(oid))

    def register(self, oid, key, value, readonly=True):
        """Register Item to tree

        Register new Item to the tree with provided oid, key, value

        Returns the created item
        """
        return self.add(Item(oid, key, value))

    def add(self, item):
        """Add an item to tree

        Add an item to the tree. Item must be OIDPrefix instance.

        Returns the registered item.
        """
        if not isinstance(item, OIDPrefix):
            raise SNMPError('Can only add OIDPrefix objects to tree')

        if not self.match(item):
            raise SNMPError('OID prefix does not match: %s' % item.oid_string)

        for i, existing in enumerate(self.items):

            if isinstance(existing, Tree) and existing.match(item):
                return existing.add(item)

            if item < existing:
                return self.__register__(item, i, existing)

            if item == existing:
                raise SNMPError('OID already registered: %s' % item.oid)

        return self.__register__(item, len(self.items))

    def add_values(self, key, values, index=None, readonly=True):
        """Add a list of values

        Add a list of values as Item entries with given key, starting
        from given index. If index is None, first index is last + 1

        """
        if key not in SNMP_DATA_TYPE_MAP:
            raise SNMPError('Invalid key %s' % key)

        if not isinstance(values, list):
            raise SNMPError('Values must be a list of simple values: %s' % values)

        if index is None:
            if self.items:
                self.log.debug('Lookup relative OID from %s' % self.items[-1])
                index = self.relative_oid(self.items[-1].oid)
                index[-1] += 1
            else:
                index = [1]

        for value in values:
            oid = [x for x in self.oid] + index
            self.register(oid, key, value, readonly)
            index[-1] += 1

        return self

    def add_prefix_map(self, prefixes):
        """Add a list of mapped prefixes

        Add a list of mapped prefixes, for example:

            tree = agent.register_tree('1.2.3.4.4')
            tree.add_prefix_map([
                { 'oid': '1.2.3.4.4.1', 'key': 'string', 'values': [x for x in string.letters[:10]]},
                { 'oid': '1.2.3.4.4.2', 'key': 'integer', 'readonly': False, 'values': [x for x in string.digits[:10]]},
            ])

            Each list must have equal number of values: think of ifIndex and ifInOctets

            Returns nothing
        """
        try:
            if not isinstance(prefixes, list):
                raise ValueError('Prefixes must be a list')

            # Validate prefixes before insert
            length = None
            for prefix in prefixes:
                if not isinstance(prefix, dict):
                    raise ValueError

                if 'oid' in prefix:
                    prefix['oid'] = self.__format_oid__(prefix['oid'])
                    self.relative_oid(prefix['oid'])
                else:
                    raise ValueError('Missing oid: %s' % prefix)

                if 'key' in prefix:
                    try:
                        callback = SNMP_DATA_TYPE_MAP[prefix['key']]
                    except KeyError:
                        raise ValueError('Invalid prefix key %s' % prefix)
                else:
                    raise ValueError('Missing key: %s' % prefix)

                if 'readonly' in prefix:
                    prefix['readonly'] = prefix['readonly'] and True or False
                else:
                    prefix['readonly'] = True

                if 'values' in prefix:
                    items = prefix['values']

                    if not isinstance(items, list):
                        raise ValueError('Items not a list')

                    if len(items)==0 or length is not None and len(items) != length:
                        raise ValueError('Invalid values list length: %s' % prefix)

                else:
                    raise ValueError('Missing values: %s' % prefix)

        except ValueError:
            raise SNMPError('Invalid prefixes format: %s' % prefixes)

        for prefix in prefixes:
            tree = self.add(Tree(prefix['oid']))
            tree.add_values(prefix['key'], prefix['values'], readonly=prefix['readonly'])

    def GET(self, oid):
        """Return OID from tree

        Return value for matching OID from tree or None

        """
        try:
            formatted = self.__format_oid__(oid)
            oidstring = self.__format_oid_string__(oid)
        except ValueError:
            return self.__invalid__('GET invalid OID %s' % oid)

        if formatted == self.oid:
            return self.__invalid__('GET for OID tree root %s' % oidstring)

        try:
            entry = self.item_index[oidstring]

            if isinstance(entry, Tree):
                return entry.GET(oid)

            if isinstance(entry, Item):
                if entry.value is not None:
                    return entry
                else:
                    return __invalid__('Tree %s entry %s not initialized' % (self, entry))

        except KeyError:
            pass

        for tree in self.subtrees:
            if tree.match(formatted):
                return tree.GET(oid)

        return None

    def NEXT(self, oid):
        """Return next OID from tree

        Return value for matching next OID from tree or None

        """
        try:
            formatted = self.__format_oid__(oid)
        except ValueError:
            return self.__invalid__('GET invalid OID')

        if formatted == self.oid:
            if not len(self.items):
                return self.__invalid__('NEXT for root of empty tree %s' % self.oidstring)
            next = self.items[0]

            if isinstance(next, Tree):
                return next.NEXT(next.oid_string)

            if hasattr(next, 'value'):
                return next

            else:
                raise SNMPError('ERROR getting NEXT from %s' % next)

        for tree in self.subtrees:
            if tree.match(oid):
                return tree.NEXT(oid)

        try:
            index = self.__format_oid_string__(oid)
        except ValueError:
            return self.__invalid__('NEXT invalid OID %s' % oid)

        try:
            entry = self.item_index[index]
        except KeyError:
            if self.items:
                return self.items[0]
            else:
                return self.__invalid__('NEXT unknown OID %s' % oid)

        if isinstance(entry, Tree):
            return entry.NEXT(oid)

        if isinstance(entry.next, Tree):
            return entry.next.NEXT(oid)

        if entry.next:
            return entry.next
        elif self.next:
            return self.next.NEXT(oid)
        else:
            self.__invalid__('NEXT unknown OID %s' % oid)

    def SET(self, oid, value):
        """Set OID value

        Set value for OID in tree. Item matching OID must exist before SET.

        Returns error code string or DONE if successful
        """
        entry = self.GET(oid)
        if entry is None:
            return 'not-writable'

        if not hasattr(entry, 'value') or entry.readonly:
            self.log.debug('error writing entry %s: %s %s' % (entry, type(entry), hasattr(entry, 'value')))
            return 'not-writable'

        try:
            value = SNMP_DATA_TYPE_MAP[entry.key](value)
        except ValueError:
            return 'wrong-type'

        if not entry.check_length(value):
            return 'wrong-length'

        if not entry.check_value(value):
            return 'wrong-value'

        if not entry.check_value_consistency(value):
            return 'inconsistent-value'

        entry.value = value
        return 'DONE'

class SNMPAgent(Script):
    """SNMP Agent implementation

    SNMP agent daemon for net-snmpd pass_persist mode

    Example usage:

        agent = SNMPAgent('.1.2.3.4')
        tree = agent.register_tree('1.2.3.4.1')
        tree.register('1.2.3.4.1.1', 'integer', 1)
        tree.register('1.2.3.4.1.2', 'integer', 2)

        agent.register_tree('1.2.3.4.2')
        agent.register('1.2.3.4.2.1', 'integer', 1)
        agent.register('1.2.3.4.2.4', 'integer', 4)
        agent.register('1.2.3.4.2.3', 'integer', 3)
        agent.register('1.2.3.4.2.2', 'integer', 2)

        tree = agent.register_tree('1.2.3.4.3')
        tree.register('1.2.3.4.3.1.1', 'integer', 1)
        tree.add_values('string', [x for x in string.digits[2:]])

        tree = agent.register_tree('1.2.3.4.4')
        tree.add_prefix_map([
            { 'oid': '1.2.3.4.4.1', 'key': 'string', 'values': [x for x in string.letters[:10]]},
            { 'oid': '1.2.3.4.4.2', 'key': 'integer', 'values': [x for x in string.digits[:10]]},
        ])

        agent.run()
    """
    def __init__(self, oid, reload_interval=60):
        super(SNMPAgent, self).__init__()
        self.log = Logger('snmp').default_stream

        self.reload_interval = reload_interval
        self.last_reload = None
        self.args = None

        self.add_argument('-g', '--get', help='SNMP GET request')
        self.add_argument('-n', '--next', help='SNMP GET request')
        self.add_argument('-t', '--tree', action='store_true', help='Show OID tree')

        self.tree = Tree(oid)

    def __SIGHUP__(self, signum, frame):
        """
        Signal handler to reload configuration. Note this requires also the
        IOError processing in main input loop below
        """
        self.log.debug('Reloading from signal')
        self.reload()

    def parse_args(self):
        if self.args is None:
            self.args = super(SNMPAgent, self).parse_args()
        return self.args

    def register_tree(self, oid):
        return self.tree.add(Tree(oid))

    def register(self, oid, key, value):
        return self.tree.add(Item(oid, key, value))

    def GET(self, oid):
        """GET from agent

        Return given OID from agent tree or None

        """
        try:
            return self.tree.GET(oid)
        except SNMPError, emsg:
            self.log.debug(emsg)
            return None

    def NEXT(self, oid):
        """NEXT from agent

        Return given NEXT from agent tree or None

        """
        try:
            return self.tree.NEXT(oid)
        except SNMPError, emsg:
            self.log.debug(emsg)
            return None

    def SET(self, oid, value):
        """SET registered OID

        Set value for registered OID in agent tree.

        Note: By default items registered are readonly.


        """
        return self.tree.SET(oid, value)

    def clear(self):
        return self.tree.clear()

    def reload(self):
        """
        This method must be implemented in a child class. It is used to
        reload the SNMP tree data from files, if possible.
        """
        raise NotImplementedError('You must implement reload in child class')

    def run(self):
        """SNMP Agent main loop

        Main loop to execute for agent. You can either run this in:

        - 'pass' mode: get/next for single OID by passing in OptionParser
          'options' value 'get' or 'next' (snmpd.conf 'pass' agent)
        - 'pass_persist' mode: without any options, in which case the loop
           acts as permanent snmpd pass_persist agent.
        """

        self.args = self.parse_args()

        signal.signal(signal.SIGHUP, self.__SIGHUP__)

        if self.args.tree:
            self.message(self.tree.oid_string)

        elif self.args.get:
            entry = self.GET(self.args.get)
            if entry is not None:
                sys.stdout.write('%s\n' % entry.get_response)

        elif self.args.next:
            entry = self.NEXT(self.args.next)
            if entry is not None:
                sys.stdout.write('%s\n' % entry.next_response)

        if self.args.tree or self.args.get or self.args.next:
            self.exit(0)

        EOF = ''
        self.log.debug('Starting SNMP agent for OID %s' % self.tree.oid)

        while True:
            ready = select.select([sys.stdin], [], [], 0.2)[0]
            if not ready:
                if self.last_reload is not None:
                    since_reload = time.time() - self.last_reload
                    if since_reload > self.reload_interval:
                        self.reload()
                        self.last_reload = time.time()
                else:
                    self.last_reload = time.time()
                continue

            try:
                cmd = sys.stdin.readline()
                if cmd == EOF:
                    break
                if cmd.strip() == '':
                    self.log.debug('Received agent shutdown')
                    break

                cmd = cmd.rstrip().lower()

                if cmd == 'quit':
                    return

                if cmd == 'reload':
                    self.reload()

                if cmd == 'ping':
                    sys.stdout.write('PONG\n')

                if cmd in ('set', 'get', 'getnext'):
                    oid = sys.stdin.readline()
                    if oid == EOF:
                        break
                    oid = oid.rstrip()

                if cmd == 'set':
                    value = sys.stdin.readline()
                    if value == EOF:
                        break
                    result = self.SET(oid, value)
                    sys.stdout.write('%s\n' % result)

                elif cmd == 'get':
                    entry = self.GET(oid)
                    if entry is not None:
                        sys.stdout.write('%s\n' % entry.get_response)
                    else:
                        sys.stdout.write('NONE\n')

                elif cmd == 'getnext':
                    entry = self.NEXT(oid)
                    if entry is not None:
                        sys.stdout.write('%s\n' % entry.next_response)
                    else:
                        sys.stdout.write('NONE\n')

                else:
                    self.log.debug('Unknown command (should be get/set/getnext)')
                sys.stdout.flush()

            except IOError, emsg:
                # we get EINTR with SIGHUP and we can ignore it
                if emsg[0]==errno.EINTR:
                    continue
                self.log.debug('IOError: %s' % emsg[1])
                return

            except KeyboardInterrupt:
                # Interactive mode, user interrupted
                self.log.debug('Quitting...')
                return
