#!/usr/bin/env python
"""
Module for abstract resolver queries with dns-python to easy to use
functions.

This is used mainly to query arbitrary servers for all values, not
just one of the values like with DNS lookups, and to return the data
as an easily understandable dictionary.
"""

import socket

from seine.dns import DNSError
import dns.resolver, dns.query, dns.rdatatype
import dns.rdtypes.ANY, dns.rdtypes.IN

class QueryError(Exception):
    pass

# Map dns.rdtypes subclass pahts to attributes to fetch from the response
# class name
RDTYPE_NAME_MAP = {
    'dns.rdtypes.ANY.SOA':   [
        'serial', 'retry', 'refresh', 'expire', 'minimum', 'mname', 'rname',
    ],
    'dns.rdtypes.ANY.NS':    ['target'],
    'dns.rdtypes.IN.A':      ['address'],
    'dns.rdtypes.IN.AAAA':   ['address'],
    'dns.rdtypes.ANY.PTR':   ['target'],
    'dns.rdtypes.ANY.CNAME': ['target'],
    'dns.rdtypes.ANY.MX':    ['preference', 'exchange'],
    'dns.rdtypes.ANY.TXT':   ['strings'],
    'dns.rdtypes.ANY.SSHFP': ['algorithm', 'fingerprint'],
}
# Initialize a dictionary with the class references from dns.rdtypes
RDTYPE_DICT_MAP = {}
for path in RDTYPE_NAME_MAP.keys():
    name = path.split('.')[-1]
    m = __import__(path, globals(), fromlist=[name])
    nk = getattr(m, name)
    RDTYPE_DICT_MAP[nk] = RDTYPE_NAME_MAP[path]

def rrname_mapped(value):
    """
    Checks if given rrtype value is supported (mapping from dns module
    data structures is implemented). Returns the rrname in uppercase or
    raises ValueError if rrtype is not implemented.
    """
    rrname = value.upper()
    if rrname not in map(lambda x: x.split('.')[-1], RDTYPE_NAME_MAP.keys()):
        raise ValueError('RR name %s not yet supported.' % rrname)

    return rrname

def resolve_records(query, nameserver, rrtype='A', timeout=5):
    """
    Try resolving given query (for. example www.google.com) from given
    nameservers, querying given rrtype.

    Returns each response with given RR type as a dictionary, containing
    details relevant for the query in question. Returns empty list if no
    details could be found.
    """

    try:
        rrname = rrname_mapped(rrtype)
    except ValueError, e:
        raise ValueError(e)

    try:
        rdtype = getattr(dns.rdatatype, rrname)
    except AttributeError:
        raise ValueError('Unsupported RR name %s' % rrname)

    try:
        timeout = int(timeout)
    except ValueError:
        raise ValueError('Invalid query timeout value: %s' % timeout)

    try:
        response = dns.query.udp(
            q=dns.message.make_query(query, rdtype),
            where=nameserver, timeout=timeout
        )
    except socket.error, (ecode, emsg):
        raise QueryError('Nameserver %s: %s' % (nameserver, emsg))
    except dns.exception.Timeout:
        raise QueryError('Timeout resolving from %s' % nameserver)

    authority = []
    for rs in response.authority:
        for r in rs:
            try:
                attrs = RDTYPE_DICT_MAP[type(r)]
            except KeyError:
                raise ValueError('No mapping for %s' % r.__class__)

            entry = dict([(k, getattr(r, k)) for k in attrs])
            entry['rdclass'] = dns.rdataclass.to_text(r.rdclass)
            entry['rrtype'] = dns.rdatatype.to_text(r.rdtype)

            authority.append(entry)

    additional = []
    for rs in response.additional:
        for r in rs:
            try:
                attrs = RDTYPE_DICT_MAP[type(r)]
            except KeyError:
                raise ValueError('No mapping for %s' % r.__class__)

            entry = dict([(k, getattr(r, k)) for k in attrs])
            entry['name'] = rs.name
            entry['rdclass'] = dns.rdataclass.to_text(r.rdclass)
            entry['rrtype'] = dns.rdatatype.to_text(r.rdtype)
            additional.append(entry)

    results = []
    for rs in filter(lambda rs: rs.rdtype == rdtype, response.answer):
        for r in rs:
            try:
                attrs = RDTYPE_DICT_MAP[type(r)]
            except KeyError:
                raise ValueError('No mapping for %s' % r.__class__)

            entry = dict([(k, getattr(r, k)) for k in attrs])
            entry['name'] = rs.name
            entry['rdclass'] = dns.rdataclass.to_text(r.rdclass)
            entry['rrtype'] = dns.rdatatype.to_text(r.rdtype)
            results.append(entry)

    return {
        'results': results,
        'authority': authority,
        'additional': additional,
    }

