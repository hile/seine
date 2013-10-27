#!/usr/bin/env python
"""
Agent to represent Dell server SNMP monitoring
"""

class DellServer(dict):
    def __init__(self,snmp_client):
        self.client = snmp_client

