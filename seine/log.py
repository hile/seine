#!/usr/bin/env python
"""
Abstraction for logging in Seine modules.
"""

import os,logging
import logging.handlers

DEFAULT_LOGFORMAT = '%(name)s %(levelname)s %(message)s'
DEFAULT_LOGFILEFORMAT = '%(asctime)s %(name)s[%(process)d] %(levelname)s: %(message)s'

class SeineLogs(dict):
    def __init__(self,program='seine'):
        self.config = config
        self.program = program
        for name in ['console','modules']:
            l = logging.getLogger(name)
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter(config.logging['logformat']))
            l.addHandler(h)
            self[name] = l

    def __setattr__(self,attr,value):
        object.__setattr__(self,attr,value)
        if attr == 'level':
            for name,logger in self.items():
                logger.setLevel(self.level)

