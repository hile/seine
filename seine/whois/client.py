#!/usr/bin/env python
"""
Nagios test module to query whois servers for a domain's data,
use by libexec/check_whois script to check expiration status.
"""

import sys
import os
import logging
import time
import socket
import select

from seine.address import IPv4Address, IPv6Address
from seine.whois import WhoisError
from seine.whois.cache import WhoisServerCache
from seine.whois.parsers import WhoisData

WHOIS_PORT = 43
WHOIS_SERVER_TIMEOUT = 15
WHOIS_BUFFER_SIZE = 1024

TLD_REQUIRES_EQUALS = ['com']

logger = logging.getLogger()

class WhoisClient(object):
    def __init__(self):
        self.cache = WhoisServerCache()

    def query(self, domain):
        data = WhoisData(domain)
        data.query(self.cache.query(domain))
        try:
            self.cache.save()
        except WhoisError, emsg:
            logger.debug(emsg)
            pass

        return data
