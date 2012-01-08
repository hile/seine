#!/usr/bin/env python
"""
Generic SNMP device process listing monitoring classes
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

PROCESS_OIDS_MAP = {
    'index': { 
        'oid': '.1.3.6.1.2.1.25.4.2.1.1',
        'decode': lambda oid,x: (oid,int(x)), 
    },
    'name': {
        'oid': '.1.3.6.1.2.1.25.4.2.1.2',
        'decode': lambda oid,x: (oid,str(x)),
    },
    'args': {
        'oid': '1.3.6.1.2.1.25.4.2.1.5',
        'decode': lambda oid,x: (oid,str(x)),
    },
    'mem': {
        'oid': '.1.3.6.1.2.1.25.5.1.1.2', 
        'decode': lambda oid,x: (oid,int(x)),
    },
    'cputime': { 
        'oid': '.1.3.6.1.2.1.25.5.1.1.1', 
        'decode': lambda oid,x: (oid,int(x)),
    },
    'runstate': { 
        'oid': '.1.3.6.1.2.1.25.4.2.1.7', 
        'decode': lambda oid,x: (oid,int(x)), 
    },
}

class SNMPProcessIndexCache(dict):
    def __init__(self,path=None):
        self.path = path
        self.load()

    def load(self):
        if self.path is None or not os.path.isfile(self.path):
            return
        for host,opts in ConfigObj(self.path).items():
            self[host] = dict(opts)

    def save(self):
        if self.path is None:   
            return
        c = ConfigObj()
        for host,opts in self.items():
            if len(opts)==0:
                continue
            if not c.has_key(host):
                c[host] = {}
            for index,details in opts.items():
                index = str(index)
                c[host][index] = details
        c.write(open(self.path,'w'))

class SNMPProcessStatus(SNMPClient):
    """
    Cacheable dictionary of process details: pid, name, args mem, cputime 
    """
    def __init__(self,oid_map=PROCESS_OIDS_MAP,*args,**kwargs):
        SNMPClient.__init__(self,oid_map=PROCESS_OIDS_MAP,*args,**kwargs)

    def __getattr__(self,attr):
        if attr in PROCESS_OIDS_MAP.keys():
            d = PROCESS_OIDS_MAP[attr]
            oid = d['oid']
            return [d['decode'](k,v) for k,v in self.walk(oid).items()]
        raise AttributeError('No such SNMPProcessStatus attribute: %s' % attr)

    def update_indexes(self):
        self.indexes = {}
        self.log.info('Loading indexes')
        for section in ['index','name','args','mem','cputime']:
            for k,v in getattr(self,section):
                index = int(k.split('.')[-1])
                if not self.indexes.has_key(index):
                    self.indexes[index] = {}
                if section in ['mem','cputime','index']:
                    v = int(v)
                self.indexes[index][section] = v
        self.index_cache[self.address] = dict(self.indexes)
        self.index_cache.save()

