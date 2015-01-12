#!/usr/bin/env python

import os
import glob
from setuptools import setup, find_packages

VERSION='2.4.5'

setup(
    name = 'seine',
    version = VERSION,
    license = 'PSF',
    keywords = 'Network Utility Functions',
    url = 'http://tuohela.net/packages/seine',
    zip_safe = False,
    scripts = glob.glob('bin/*'),
    packages = ['seine'] + ['seine.%s'%s for s in find_packages('seine')],
    author = 'Ilkka Tuohela',
    author_email = 'hile@iki.fi',
    description = 'Various network address and url related utilities',
    install_requires = [
        'systematic>=4.0.5',
        'requests',
        'python-dateutil',
        'pyopenssl',
        'dnspython',
        'pyip',
        'pyasn1',
        'pysnmp'
    ],
)

