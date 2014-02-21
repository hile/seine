#!/usr/bin/env python
"""
Parser classes for various whois output formats
"""

import os

from seine.whois import WhoisError
from seine.whois.formats.ficora import ficora
from seine.whois.formats.gtld import gtld
from seine.whois.formats.nominet import nominet
from seine.whois.formats.saudinic import saudinic

WHOIS_PARSERS = (
    ficora, gtld, nominet, saudinic
)


class WhoisData(dict):
    def __init__(self, domain):
        self.parsers = WHOIS_PARSERS
        self.domain = domain

    def __repr__(self):
        return 'WHOIS for %s' % self.domain

    @property
    def name(self):
        try:
            return self['domainname']
        except KeyError:
            return self.domain

    @property
    def status(self):
        try:
            return self['status']
        except KeyError:
            return []

    @property
    def nameservers(self):
        try:
            return sorted(x.lower() for x in self['nameservers'])
        except KeyError:
            return []

    @property
    def created(self):
        try:
            return self['created']
        except KeyError:
            return None

    @property
    def expires(self):
        try:
            return self['expires']
        except KeyError:
            return None

    @property
    def modified(self):
        try:
            return self['modified']
        except KeyError:
            return None

    def query(self, data):
        data_parsers = [x for x in self.parsers if x().matches_domain(self.domain)]
        if len(data_parsers) > 1:
            raise WhoisError('BUG: more than one parser for domain %s: %s' % (
                self.domain,
                [x.name for x in data_parsers]
            ))

        if not data_parsers:
            raise WhoisError('No whois data parser found for domain %s' % self.domain)

        formatter = data_parsers[0]()
        formatter.parse(self.domain, data)
        self.update(formatter.items())


