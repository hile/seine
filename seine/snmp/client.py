
"""
SNMP client classes to simplify using pysnmp
"""

import sys
import os
import socket
from configobj import ConfigObj

from systematic.log import Logger, LoggerError

from pyasn1.error import PyAsn1Error, SubstrateUnderrunError, ValueConstraintError
from pysnmp.carrier.error import CarrierError

from pysnmp.entity import config as snmpconfig
from pysnmp.entity.rfc3413.oneliner.cmdgen import CommunityData, UsmUserData
from pysnmp.entity.rfc3413.oneliner.cmdgen import UdpTransportTarget
from pysnmp.entity.rfc3413.oneliner.cmdgen import CommandGenerator

from seine.snmp import cmp_oid, SNMPError, SNMP_VERSIONS

DEFAULT_AGENT = 'seine'
DEFAULT_PORT = 161
DEFAULT_TIMEOUT = 1
DEFAULT_RETRIES = 5
DEFAULT_VERSION='2c'
DEFAULT_V3_AUTH_PROTOCOL = 'SHA'
DEFAULT_V3_PRIV_PROTOCOL = 'AES'

V3_AUTH_PROTOCOLS = {
    'MD5': snmpconfig.usmHMACMD5AuthProtocol,
    'SHA': snmpconfig.usmHMACSHAAuthProtocol,
    'NOAUTH': snmpconfig.usmNoAuthProtocol,
}
V3_PRIV_PROTOCOLS = {
    'DES': snmpconfig.usmDESPrivProtocol,
    'AES': snmpconfig.usmAesCfb128Protocol,
    'NOPRIV': snmpconfig.usmNoPrivProtocol,
}

class SNMPAuth(object):
    """SNMP authentication base class

    Base class for SNMP*Auth classes

    """
    def __init__(self, version):
        if version not in SNMP_VERSIONS:
            raise SNMPError('Invalid SNMP version: %s' % version)
        self.version = version
        self.auth = None

class SNMPv1Auth(SNMPAuth):
    """SNMP v1 community authentication

    Authenticate with SNMP v1 community

    """
    def __init__(self, community, securityname=DEFAULT_AGENT):
        SNMPAuth.__init__(self, '1')
        self.community = community
        self.securityname = securityname
        self.auth = CommunityData(self.securityname, self.community, 0)

    def __repr__(self):
        return '%s SNMP v1 community %s' % (self.securityname, self.community)

class SNMPv2cAuth(SNMPAuth):
    """SNMP v2c community authentication

    Authenticate with SNMP v2c community

    """
    def __init__(self, community, securityname=DEFAULT_AGENT):
        SNMPAuth.__init__(self, '2c')
        self.community = community
        self.securityname = securityname
        self.auth = CommunityData(self.securityname, self.community)

    def __repr__(self):
        return '%s SNMP v2c community %s' % (self.securityname, self.community)

class SNMPv3Auth(SNMPAuth):
    """SNMP v3 community authentication

    Authenticate with SNMP v3 username, authentication password and optionally
    with separate privacy password.

    You can set authentication protocol and privacy protocol as well, supported
    protocols depend on pysnmp support for the method.

    """
    def __init__(self, username, authPass, privPass=None,
                 authProtocol=DEFAULT_V3_AUTH_PROTOCOL, privProtocol=DEFAULT_V3_PRIV_PROTOCOL):

        SNMPAuth.__init__(self, '3')
        self.username = username
        self.authPass = authPass
        self.privPass = privPass is not None and privPass or authPass

        self.auth_name = authProtocol
        self.priv_name  = privProtocol

        self.auth = UsmUserData( self.username,
            authKey=self.authPass, privKey=privPass,
            authProtocol=self.__lookup_auth_protocol(authProtocol),
            privProtocol=self.__lookup_priv_protocol(privProtocol),
        )

    def __repr__(self):
        return 'SNMP v3 auth: user %s auth %s encryption %s' % (
            self.username, self.auth_name, self.priv_name
        )

    def __lookup_auth_protocol(self,protocol):
        if not protocol:
            protocol = DEFAULT_V3_AUTH_PROTOCOL

        try:
            return V3_AUTH_PROTOCOLS[protocol.upper()]
        except KeyError:
            raise SNMPError('Unknown SNMP authentication protocol: %s' % protocol)
        except AttributeError:
            raise SNMPError('Protocol value must be a string')

    def __lookup_priv_protocol(self, protocol):
        if not protocol:
            protocol = DEFAULT_V3_PRIV_PROTOCOL

        try:
            return V3_PRIV_PROTOCOLS[protocol.upper()]
        except KeyError:
            raise SNMPError('Unknown SNMP privacy protocol: %s' % protocol)
        except AttributeError:
            raise SNMPError('Protocol value must be a string')

class SNMPIndexCache(dict):
    """Cached SNMP results

    Cache SNMP response to a file on disk

    """
    def __init__(self, path=None):
        self.path = path
        self.load()

    def load(self):
        """Load cached data

        Returns silently if file did not exist

        """
        if self.path is None or not os.path.isfile(self.path):
            return

        for (k,opts) in ConfigObj(self.path).items():
            self[k] = opts

    def save(self):
        """Save cached data

        Replace data file with current object contents

        """
        if self.path is None:
            return
        c = ConfigObj()

        for k, opts in self.items():
            if len(opts) == 0:
                continue
            if not c.has_key(k):
                c[k] = {}
            for i, data in opts.items():
                i = str(i)
                c[k][i] = data

        try:
            c.write(open(self.path, 'w'))
        except OSError, (ecode,emsg):
            raise SNMPError('Error writing index cache %s: %s' (self.path, emsg))
        except IOError, (ecode, emsg):
            raise SNMPError('Error writing index cache %s: %s' (self.path, emsg))

class SNMPClient(object):
    """
    Wrapper for SNMP SET, GET and WALK requests
    """

    def __init__(self, address, auth, port=DEFAULT_PORT, timeout=DEFAULT_TIMEOUT,
                 retries=DEFAULT_RETRIES, oid_map = {}, index_cache_path=None):

        self.logger = Logger('snmp')
        self.log = self.logger.default_stream
        self.address = address
        self.trees = {}
        self.auth_client = auth
        self.port = port
        self.timeout = timeout
        self.retries = retries

        try:
            self.target = UdpTransportTarget(
                (address, self.port),
                timeout=self.timeout,
                retries=self.retries
            )
        except socket.gaierror, emsg:
            raise SNMPError(emsg)
        except PyAsn1Error, emsg:
            raise SNMPError("ASN1 parsing error: %s" % emsg)

        self.oid_map = oid_map

        self.index_cache = SNMPIndexCache(index_cache_path)
        self.indexes = {}
        try:
            for (index, details) in self.index_cache[self.address].items():
                if details.has_key('index'):
                    details['index'] = int(details['index'])
                self.indexes[int(index)] = details

        except KeyError, emsg:
            pass

    def __repr__(self):
        return 'SNMP connection %s:%s (%s)' % (self.address, self.port, self.auth_client)

    def __getattr__(self, attr):
        if attr in self.oid_map.keys():
            config = self.oid_map[attr]
            oid = config['oid']

            try:
                return [config['decode'](k, v) for k, v in self.walk(oid).items()]
            except AttributeError:
                raise SNMPError('Invalid OID map dictionary for %s' % k)

        raise AttributeError('No such SNMPClient attribute: %s' % attr)

    def update_indexes(self):
        raise NotImplementedError('Implement update_indexes in child class')

    def set(self, oid, snmp_value):
        """
        Attempt setting the given OID to given value. Caller must prepare
        snmp_value to correct rfc1902.* reference, for example:
            rfc1902.OctetString('new name').
        """
        try:
            varBinds = tuple([
                tuple(map(lambda x:int(x), oid.lstrip('.').split('.'))),
                snmp_value
            ])
        except ValueError, emsg:
            raise SNMPError("Invalid OID: %s" % emsg)
        try:
            (e, status, index, varBinds) = CommandGenerator().setCmd(
                self.auth_client.auth,
                self.target,
                varBinds
            )

            if status != 0:
                raise SNMPError('Error setting SNMP value')

        except CarrierError, emsg:
            raise SNMPError(str(emsg))
        except socket.gaierror, emsg:
            raise SNMPError(emsg)
        except PyAsn1Error, emsg:
            raise SNMPError("ASN1 parsing error: %s" % emsg)

    def get(self, oid):
        """
        SNMP GET request to the server for given OID
        """
        try:
            oid = tuple(map(lambda x: int(x),  oid.lstrip('.').split('.')))
        except ValueError, emsg:
            raise SNMPError("Invalid OID: %s" % emsg)

        try:
            (eind, status, index, varBinds) = CommandGenerator().getCmd(
                self.auth_client.auth,
                self.target,
                oid
            )

        except CarrierError, emsg:
            raise SNMPError(str(emsg))
        except socket.gaierror, emsg:
            raise SNMPError(emsg)
        except PyAsn1Error, emsg:
            raise SNMPError("ASN1 parsing error: %s" % emsg)

        try:
            oid = varBinds[0][0]
            value = varBinds[0][1]
        except IndexError:
            raise SNMPError("No results available")

        return (oid, value)

    def walk(self, oid):
        """SNMP walk to dictionary

        Walk provided OID tree with SNMP next, return the tree as
        dictionary of (oid, value) pairs

        """
        try:
            oid = tuple(map(lambda x:int(x), oid.lstrip('.').split('.')))
        except ValueError, emsg:
            raise SNMPError("Invalid OID: %s" % emsg)
        try:
            (eind, status, index, varBinds) = CommandGenerator().nextCmd(
                self.auth_client.auth,
                self.target,
                oid
            )

        except CarrierError, emsg:
            raise SNMPError(str(emsg))
        except socket.gaierror, emsg:
            raise SNMPError(emsg)
        except PyAsn1Error, emsg:
            raise SNMPError("ASN1 parsing error: %s" % emsg)

        return dict(('.'.join(str(x) for x in v[0][0]), v[0][1]) for v in varBinds)

    def tree_key(self, oid):
        """Construct OID tree keys

        Returns a formatted OID tree key from provided string or list

        """
        try:
            if type(oid) != list:
                oid = [int(i) for i in oid.lstrip('.').split('.')]
            oid = [int(i) for i in oid]
            return '.'.join(str(i) for i in oid)

        except ValueError:
            raise SNMPError('Invalid OID: %s' % oid)

    def tree_indexes(self, oid):
        """Return OIDs mathcing prefix

        Return OID tree indexes matching provided OID from self.trees

        """
        oid = self.tree_key(oid)
        try:
            return map(lambda k: k.split('.')[-1], sorted(
                self.trees[oid].keys(),
                lambda x, y: cmp_oid(x, y)
            ))
        except KeyError:
            raise SNMPError('Tree not loaded: %s' % oid)

    def tree(self,oid, refetch=False, indexed=False):
        """Walk and store tree to self.trees

        Wrapper to self.walk to store tree results to self.trees for
        further processing

        """
        tree_id = self.tree_key(oid)
        if not refetch and self.trees.has_key(tree_id):
            tree = self.trees[tree_id]
        else:
            try:
                tree = self.walk(oid)
                self.trees[tree_id] = tree
            except CarrierError, emsg:
                raise SNMPError(str(emsg))
            except SNMPError, emsg:
                raise SNMPError(str(emsg))

        if indexed is True:
            keys = sorted(tree.keys(), lambda x, y: cmp_oid(x, y))
            return [(k.lstrip('.').split('.')[-1], tree[k]) for k in keys]
        else:
            return tree

    def fetch_trees(self, oids, refetch=False):
        """Walk and store multiple trees

        Wrapper to walk and store trees for provided OIDs to self.trees

        """
        if not isinstance(oids, list):
            raise SNMPError('Arguments oids must be a list')

        for oid in oids:
            self.tree(oid, refetch=refetch)

    def map_trees(self, oid_config):
        """Example wrappper to map trees by OIDs

        """
        oids = dict([(self.tree_key(k), oid_config[k]) for k in oid_config.keys()])

        missing = filter(lambda k: not self.trees.has_key(k), oids.keys())
        if len(missing)>0:
            raise SNMPError('Trees for OIDs not fetched: %s' % ' '.join(missing) )

        indexes = [self.tree_indexes(oid) for oid in oids.keys()]
        results = dict((int(i), {}) for i in indexes[0])
        for i in indexes[0]:
            for oid in oids.keys():
                try:
                    k = filter(lambda k: k.split('.')[-1] == i, self.trees[oid].keys())[0]
                except IndexError:
                    raise SNMPError('Error mapping OID tree %s' % oid)

                v = self.trees[oid][k]
                if results[int(i)].has_key(oid):
                    raise SNMPError('Duplicate data for %s' % oid)

                try:
                    results[int(i)][oid] = oids[oid](v)
                except ValueError:
                    results[int(i)][oid] = None

        return [(k, results[k]) for k in sorted(results.keys())]

