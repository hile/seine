#!/usr/bin/env python
"""
Generic SNMP device monitoring classes
"""

import os,re,logging
from configobj import ConfigObj

import pysnmp.error as PySNMPError
from pysnmp.proto import rfc1902

from seine.snmp import SNMPError
from seine.snmp.client import SNMPClient
from seine.address import IPv4Address,EthernetMACAddress

IF_STATUS_UP = 1 
IF_STATUS_DOWN = 2
IF_STATUS_CODES = [ None, IF_STATUS_UP, IF_STATUS_DOWN ]

INTERFACE_IPV4_OID_PREFIX = '.1.3.6.1.2.1.3.1.1.3'

NETWORK_OIDS_MAP = {
    'index': { 
        'oid': '.1.3.6.1.2.1.2.2.1.1', 
        'decode': lambda oid,x: (oid,int(x)), 
    },
    'mtu': {
        'oid': '.1.3.6.1.2.1.2.2.1.4', 
        'decode': lambda oid,x: (oid,int(x)),
    },
    'speed': {
        'oid': '.1.3.6.1.2.1.2.2.1.5', 
        'decode': lambda oid,x: (oid,int(x)),
    },
    'phys_address': {
        'oid': '.1.3.6.1.2.1.2.2.1.6', 
        'decode': lambda oid,x: (oid,EthernetMACAddress(x)),
    },
    'description': { 
        'oid': '.1.3.6.1.2.1.2.2.1.2', 
        'decode': lambda oid,x: (oid,str(x)),
    },
    'oper_status': { 
        'oid': '.1.3.6.1.2.1.2.2.1.8', 
        'decode': lambda oid,x: (oid,IF_STATUS_CODES[int(x)]), 
    },
    'admin_status': { 
        'oid': '.1.3.6.1.2.1.2.2.1.7', 
        'decode': lambda oid,x: (oid,IF_STATUS_CODES[int(x)]), 
    },
    'in_octets': { 
        'oid': '.1.3.6.1.2.1.2.2.1.10', 
        'decode': lambda oid,x: (oid,long(x)),
    },
    'in_ucast_pkts': { 
        'oid': '.1.3.6.1.2.1.2.2.1.11', 
        'decode': lambda oid,x: (oid,long(x)),
    },
    'in_non_ucast_pkts': { 
        'oid': '.1.3.6.1.2.1.2.2.1.12', 
        'decode': lambda oid,x: (oid,long(x)),
    },
    'in_discards': { 
        'oid': '.1.3.6.1.2.1.2.2.1.13', 
        'decode': lambda oid,x: (oid,long(x)),
    },
    'in_errors': { 
        'oid': '.1.3.6.1.2.1.2.2.1.14', 
        'decode': lambda oid,x: (oid,long(x)),
    },
    'in_unknown_proto': { 
        'oid': '.1.3.6.1.2.1.2.2.1.15', 
        'decode': lambda oid,x: (oid,long(x)),
    },
    'out_octets': { 
        'oid': '.1.3.6.1.2.1.2.2.1.16', 
        'decode': lambda oid,x: (oid,long(x)),
    },
    'out_ucast_pkts': { 
        'oid': '.1.3.6.1.2.1.2.2.1.17', 
        'decode': lambda oid,x: (oid,long(x)),
    },
    'out_non_ucast_pkts': { 
        'oid': '.1.3.6.1.2.1.2.2.1.18', 
        'decode': lambda oid,x: (oid,long(x)),
    },
    'out_discards': { 
        'oid': '.1.3.6.1.2.1.2.2.1.19', 
        'decode': lambda oid,x: (oid,long(x)),
    },
    'out_errors': { 
        'oid': '.1.3.6.1.2.1.2.2.1.20', 
        'decode': lambda oid,x: (oid,long(x)),
    },
    'out_qlen': { 
        'oid': '.1.3.6.1.2.1.2.2.1.21', 
        'decode': lambda oid,x: (oid,long(x)),
    },
    'name': { 
        'oid': '.1.3.6.1.2.1.31.1.1.1.1',
        'decode': lambda oid,x: (oid,str(x)),
    },
    'in_mcast_pkts': { 
        'oid': '.1.3.6.1.2.1.31.1.1.1.2',
        'decode': lambda oid,x: (oid,long(x)),
    },
    'in_bcast_pkts': { 
        'oid': '.1.3.6.1.2.1.31.1.1.1.3',
        'decode': lambda oid,x: (oid,long(x)),
    },
    'out_mcast_pkts': { 
        'oid': '.1.3.6.1.2.1.31.1.1.1.4',
        'decode': lambda oid,x: (oid,long(x)),
    },
    'out_bcast_pkts': { 
        'oid': '.1.3.6.1.2.1.31.1.1.1.5',
        'decode': lambda oid,x: (oid,long(x)),
    },
    'in_64bit_octets': { 
        'oid': '.1.3.6.1.2.1.31.1.1.1.6',
        'decode': lambda oid,x: (oid,long(x)),
    },
    'in_64bit_ucast_pkts': { 
        'oid': '.1.3.6.1.2.1.31.1.1.1.7',
        'decode': lambda oid,x: (oid,long(x)),
    },
    'in_64bit_mcast_pkts': { 
        'oid': '.1.3.6.1.2.1.31.1.1.1.8',
        'decode': lambda oid,x: (oid,long(x)),
    },
    'in_64bit_bcast_pkts': { 
        'oid': '.1.3.6.1.2.1.31.1.1.1.9',
        'decode': lambda oid,x: (oid,long(x)),
    },
    'out_64bit_octets': { 
        'oid': '.1.3.6.1.2.1.31.1.1.1.10',
        'decode': lambda oid,x: (oid,long(x)),
    },
    'out_64bit_ucast_pkts': { 
        'oid': '.1.3.6.1.2.1.31.1.1.1.11',
        'decode': lambda oid,x: (oid,long(x)),
    },
    'out_64bit_mcast_pkts': { 
        'oid': '.1.3.6.1.2.1.31.1.1.1.12',
        'decode': lambda oid,x: (oid,long(x)),
    },
    'out_64bit_bcast_pkts': { 
        'oid': '.1.3.6.1.2.1.31.1.1.1.13',
        'decode': lambda oid,x: (oid,long(x)),
    },
    'updown_trap_enable': { 
        'oid': '.1.3.6.1.2.1.31.1.1.1.14',
        'decode': lambda oid,x: (oid,int(x)== 1 and True or False),
    },
    'speed_fastlink': { 
        'oid': '.1.3.6.1.2.1.31.1.1.1.15',
        'decode': lambda oid,x: (oid,long(x)),
    },
    'promiscuous': { 
        'oid': '.1.3.6.1.2.1.31.1.1.1.16',
        'decode': lambda oid,x: (oid,int(x)== 1 and True or False),
    },
    'connector_present': { 
        'oid': '.1.3.6.1.2.1.31.1.1.1.17',
        'decode': lambda oid,x: (oid,int(x)== 1 and True or False),
    },
    'alias': { 
        'oid': '.1.3.6.1.2.1.31.1.1.1.18',
        'decode': lambda oid,x: (oid,str(x)),
    },
}

class SNMPNetworkInterfaces(SNMPClient):
    def __init__(self,*args,**kwargs):
        SNMPClient.__init__(self,oid_map=NETWORK_OIDS_MAP,*args,**kwargs)

    def update_indexes(self):
        self.indexes = {}
        self.log.info('Loading indexes')
        for section in ['index','name','description']:
            for k,v in getattr(self,section):
                index = int(k.split('.')[-1])
                if not self.indexes.has_key(index):
                    self.indexes[index] = {}
                self.indexes[index][section] = v
        self.index_cache[self.address] = self.indexes
        self.index_cache.save()

    def set_alias(self,ifindex,value):
        try:
            ifindex = int(ifindex)
            if ifindex not in self.indexes.keys():
                raise ValueError
        except ValueError:
            raise ValueError('Invalid ifindex')
        oid = '.'.join([NETWORK_OIDS_MAP['alias']['oid'],str(ifindex)])
        print oid
        try:
            value = rfc1902.OctetString(value)
            self.set(oid,value)
        except SNMPError,emsg:
            raise ValueError('Error updating alias: %s' % emsg)

    def interface_ipv4_addresses(self,ifindex):
        if_oid = '.'.join([INTERFACE_IPV4_OID_PREFIX,str(ifindex)])
        addresses = []
        for (oid,value) in self.walk(if_oid).items():
            try:
                addresses.append(IPv4Address(value))
            except ValueError:
                raise ValueError('Invalid IPv4 address from OID %s' % oid)
        return addresses  

    def interface_names(self):
        if self.indexes == {}:
            self.update_indexes()
        return self.indexes

    def interface_details(self,ifindex,fields=None):
        if self.indexes == {}:
            self.update_indexes()
        try:
            ifindex = int(ifindex)
            if ifindex not in self.indexes.keys():
                raise ValueError
        except ValueError:
            raise ValueError('Invalid ifindex value %s' % ifindex)
        details = {}
        if fields is not None:
            for f in fields:
                if f not in NETWORK_OIDS_MAP.keys():
                    raise ValueError('Invalid field name %s' % f)
        else:
            fields = NETWORK_OIDS_MAP.keys()
        for k in fields:
            d = NETWORK_OIDS_MAP[k]
            oid = '.'.join([d['oid'],str(ifindex)])
            try:
                (oid,value) = self.get(oid)
                try:
                    details[k] = d['decode'](oid,value)[1]
                except AttributeError:
                    details[k] = None
            except ValueError:
                raise ValueError('Error parsing oid %s' % oid)
        if fields is None:
            details['ipv4_addresses'] = self.interface_ipv4_addresses(ifindex)
        return details

    def interface_status(self,ifindexes=None):
        if self.indexes == {}:
            self.update_indexes()
        fields = ['name','description','alias','oper_status','admin_status']
        if ifindexes is None:
            details = self.indexes()
            for k in fields:
                for oid,value in getattr(self,k):
                    index = int(oid.split('.')[-1])
                    details[index][k] = value
        else:
            if type(ifindexes) != list: ifindexes = [ifindexes]
            details = {}
            for ifindex in ifindexes:
                try:
                    details[ifindex] = self.interface_details(ifindex,fields)
                except ValueError,emsg:
                    raise ValueError(emsg)
        return details

    def interface_octet_counters(self,ifindexes=None):
        if self.indexes == {}:
            self.update_indexes()
        fields =  ['in_octets','out_octets','in_64bit_octets','out_64bit_octets']
        if ifindexes is None:
            details = self.indexes()
            for k in fields:
                for oid,value in getattr(self,k):
                    index = int(oid.split('.')[-1])
                    details[index][k] = value
        else:
            if type(ifindexes) != list: ifindexes = [ifindexes]
            details = {}
            for ifindex in ifindexes:
                details[ifindex] = self.interface_details(ifindex,fields)
        return details

    def interface_packet_counters(self,ifindexes=None):
        if self.indexes == {}:
            self.update_indexes()
        fields = [
            'in_ucast_pkts','in_non_ucast_pkts',
            'out_ucast_pkts','out_non_ucast_pkts' 
        ]
        if ifindexes is None:
            details = self.indexes()
            for k in fields:
                for oid,value in getattr(self,k):
                    index = int(oid.split('.')[-1])
                    details[index][k] = value
        else:
            if type(ifindexes) != list: ifindexes = [ifindexes]
            details = {}
            for ifindex in ifindexes:
                details[ifindex] = self.interface_details(ifindex,fields)
        return details

