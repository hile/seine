#!/usr/bin/env python

import sys,socket,logging

from pyasn1.error import PyAsn1Error,SubstrateUnderrunError,ValueConstraintError 
from pysnmp.entity import config as snmpconfig
from pysnmp.entity.rfc3413.oneliner.cmdgen import CommunityData,UsmUserData
from pysnmp.entity.rfc3413.oneliner.cmdgen import UdpTransportTarget
from pysnmp.entity.rfc3413.oneliner.cmdgen import CommandGenerator

from seine.snmp import cmp_oid,SNMPError,SNMP_VERSIONS

DEFAULT_AGENT = 'seine'
DEFAULT_PORT = 161
DEFAULT_TIMEOUT = 1
DEFAULT_RETRIES = 5
DEFAULT_VERSION='2c'
DEFAULT_V3_AUTH_PROTOCOL = 'MD5'
DEFAULT_V3_PRIV_PROTOCOL = 'DES'

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
    """
    Parent class for SNMP authentication processing
    """
    def __init__(self,version):
        if version not in SNMP_VERSIONS:
            raise SNMPError('Invalid SNMP version: %s' % version)
        self.version = version
        self.auth = None

class SNMPv1Auth(SNMPAuth):
    def __init__(self,community,securityname=DEFAULT_AGENT):
        SNMPAuth.__init__(self,'1')
        self.community = community
        self.securityname = securityname
        self.auth = CommunityData(self.securityname,self.community,0)

    def __str__(self):
        return '%s SNMP v1 community %s' % (self.securityname,self.community)

class SNMPv2cAuth(SNMPAuth):
    def __init__(self,community,securityname=DEFAULT_AGENT):
        SNMPAuth.__init__(self,'2c')
        self.community = community
        self.securityname = securityname
        self.auth = CommunityData(self.securityname,self.community)

    def __str__(self):
        return '%s SNMP v2c community %s' % (self.securityname,self.community)

class SNMPv3Auth(SNMPAuth):
    def __init__(self,username,password,
                 authProtocol=DEFAULT_V3_AUTH_PROTOCOL,
                 privProtocol=DEFAULT_V3_PRIV_PROTOCOL):

        SNMPAuth.__init__(self,'3')
        self.username = username
        self.password = password

        self.auth_name = authProtocol
        self.priv_name  = privProtocol

        self.auth = UsmUserData( self.username,
            authKey=self.password,privKey=self.password,
            authProtocol=self.__lookup_auth_protocol(authProtocol),
            privProtocol=self.__lookup_priv_protocol(privProtocol),
        )

    def __str__(self):
        return 'SNMP v3 auth: user %s auth %s encryption %s' % (
            self.username,self.auth_name,self.priv_name
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
    
    def __lookup_priv_protocol(self,protocol):
        if not protocol:
            protocol = DEFAULT_V3_PRIV_PROTOCOL
        try:
            return V3_PRIV_PROTOCOLS[protocol.upper()]
        except KeyError:
            raise SNMPError('Unknown SNMP privacy protocol: %s' % protocol) 
        except AttributeError:
            raise SNMPError('Protocol value must be a string')

class SNMPClient(object):
    """
    Wrapper for SNMP SET, GET and WALK requests
    """

    def __init__(self,address,auth,
                 port=DEFAULT_PORT,timeout=DEFAULT_TIMEOUT,
                 retries=DEFAULT_RETRIES):
        self.address = address
        self.trees = {}
        self.log = logging.getLogger('modules')
        self.auth_client = auth
        self.port = port
        self.timeout = timeout
        self.retries = retries
        try:
            self.target = UdpTransportTarget(
                (address,self.port), timeout=self.timeout,retries=self.retries
            )
        except socket.gaierror,e:
            raise SNMPError(e)
        except PyAsn1Error,e:
            raise SNMPError("ASN1 parsing error: %s" % e) 

    def set(self,oid,snmp_value):
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
        except ValueError,e:
            raise SNMPError("Invalid OID: %s" % e)
        try:
            (e,status,index,varBinds) = CommandGenerator().setCmd(
                self.auth_client.auth,self.target,varBinds
            )
            if status != 0:
                raise SNMPError('Error setting SNMP value')
        except socket.gaierror,e:
            raise SNMPError(e)
        except PyAsn1Error,e:
            raise SNMPError("ASN1 parsing error: %s" % e)

    def get(self,oid):
        """
        SNMP GET request to the server for given OID
        """
        try:
            oid = tuple(map(lambda x: int(x), oid.lstrip('.').split('.'))) 
        except ValueError,e:
            raise SNMPError("Invalid OID: %s" % e)

        try:
            self.log.debug('Getting OID %s' % '.'.join(str(i) for i in oid))
            (eind,status,index,varBinds) = CommandGenerator().getCmd(
                self.auth_client.auth, self.target, oid
            )
        except socket.gaierror,e:
            raise SNMPError(e)
        except PyAsn1Error,e:
            raise SNMPError("ASN1 parsing error: %s" % e)

        try:
            oid = varBinds[0][0]
            value = varBinds[0][1]
        except IndexError:
            raise SNMPError("No results available")
        return (oid,value)

    def walk(self,oid):
        try:
            oid = tuple(map(lambda x:int(x), oid.lstrip('.').split('.'))) 
        except ValueError,e:
            raise SNMPError("Invalid OID: %s" % e)
        try:
            self.log.debug('Walking tree %s' % '.'.join(str(i) for i in oid))
            (eind,status,index,varBinds) = CommandGenerator().nextCmd(
                self.auth_client.auth, self.target, oid
            )
        except socket.gaierror,e:
            raise SNMPError(e)
        except PyAsn1Error,e:
            raise SNMPError("ASN1 parsing error: %s" % e)
        return dict(
            ('.'.join(str(x) for x in v[0][0]), v[0][1]) for v in varBinds
        )

    def tree_key(self,oid):
        try:
            if type(oid) != list:
                oid = [int(i) for i in oid.lstrip('.').split('.')]
            oid = [int(i) for i in oid]
            return '.'.join(str(i) for i in oid)
        except ValueError:
            raise NagiosPluginError('Invalid OID: %s' % oid)

    def tree_indexes(self,oid):
        oid = self.tree_key(oid)
        try:
            return map(lambda k:
                k.split('.')[-1],
                sorted(self.trees[oid].keys(),lambda x,y: cmp_oid(x,y))
            )
        except KeyError:
            raise NagiosPluginError('Tree not loaded: %s' % oid)

    def tree(self,oid,refetch=False,indexed=False):
        tree_id = self.tree_key(oid)
        if not refetch and self.trees.has_key(tree_id):
            tree = self.trees[tree_id]
        else:
            try:
                tree = self.walk(oid)
                self.trees[tree_id] = tree
            except SNMPError,emsg:
                raise NagiosPluginError(str(emsg))
        if indexed is True: 
            keys = sorted(tree.keys(),lambda x,y: cmp_oid(x,y))
            return [(k.lstrip('.').split('.')[-1],tree[k]) for k in keys]
        else:
            return tree

    def fetch_trees(self,oids,refetch=False):
        for oid in oids:
            self.tree(oid,refetch=refetch)

    def map_trees(self,oid_config):
        oids = dict([(self.tree_key(k),oid_config[k]) for k in oid_config.keys()])
        missing = filter(lambda k: not self.trees.has_key(k), oids.keys())
        if len(missing)>0:
            raise NagiosPluginError(
                'Trees for OIDs not fetched: %s' % ' '.join(missing)
            )
        
        indexes = [self.tree_indexes(oid) for oid in oids.keys()]
        #if len(indexes)>1:
        #    raise NagiosPluginError('Indexes for given OIDs are different')
        results = dict((int(i),{}) for i in indexes[0])
        for i in indexes[0]:
            for oid in oids.keys():
                k = filter(lambda k: 
                    k.split('.')[-1] == i,
                    self.trees[oid].keys()
                )[0]
                v = self.trees[oid][k]
                if results[int(i)].has_key(oid):
                    raise NagiosPluginError('Duplicate data for %s' % oid)
                try:
                    results[int(i)][oid] = oids[oid](v)
                except ValueError:
                    results[int(i)][oid] = None
        return [(k,results[k]) for k in sorted(results.keys())]

