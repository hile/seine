#!/usr/bin/env python

import os
import glob
from setuptools import setup, find_packages

VERSION='3.0.0'

setup(
    name = 'seine',
    version = VERSION,
    license = 'PSF',
    keywords = 'Network Utility Functions',
    url = 'http://tuohela.net/packages/seine',
    author = 'Ilkka Tuohela',
    author_email = 'hile@iki.fi',
    description = 'Various network address and url related utilities',
    packages = find_packages(),
    install_requires = (
        'systematic>=4.2.3',
        'requests',
        'python-dateutil',
        'dnspython',
        'pyip',
        'pyasn1',
        'pysnmp'
    ),
)

