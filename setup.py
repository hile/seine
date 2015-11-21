#!/usr/bin/env python

import os
import glob
from setuptools import setup, find_packages
from seine import __version__

setup(
    name = 'seine',
    version = __version__,
    license = 'PSF',
    keywords = 'network utility scripts and classes for python',
    url = 'https://github.com/hile/seine',
    author = 'Ilkka Tuohela',
    author_email = 'hile@iki.fi',
    description = 'Various network address and url related utilities',
    packages = find_packages(),
    scripts = glob.glob('bin/*'),
    install_requires = (
        'systematic>=4.4.0',
        'requests',
        'python-dateutil',
        'dnspython',
        'pyip',
        'pyasn1',
        'pysnmp'
    ),
)

