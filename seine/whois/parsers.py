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

    def parse(self, data):
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
        return self.update(formatter.items())

