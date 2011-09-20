#!/usr/bin/env python

import os,glob
from setuptools import setup,find_packages

VERSION='1.1'
README = open(os.path.join(os.path.dirname(__file__),'README.txt'),'r').read()

setup(
    name = 'seine',
    version = VERSION,
    license = 'PSF',
    keywords = 'Network Utility Functions',
    url = 'https://github.com/hile/seine/downloads',
    zip_safe = False,
    install_requires = ['setproctitle','dnspython'],
    scripts = glob.glob('bin/*'),
    packages = ['seine','seine.dns'],
    author = 'Ilkka Tuohela', 
    author_email = 'hile@iki.fi',
    description = 'Various network address and url related utilities',
    long_description = README,

)   

