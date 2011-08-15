#!/usr/bin/env python
"""
Wrapper function for all musa scripts, consolidating the common tasks 
required by each script.
"""

import sys,os,time,signal,logging
from optparse import OptionParser
from setproctitle import setproctitle

MYNAME = os.path.basename(sys.argv[0])

DEFAULT_LOGCONFIG= {
    'maxbytes': 2**20,
    'rotations': 10,
    'logformat': '%(name)s %(levelname)s %(message)s',
    'logfileformat': '%(asctime)s %(threadName)s[%(process)d] %(levelname)s: %(message)s',
}

def Interrupted(signum,frame):
    print 'Script interrupted'
    sys.exit(1)

def error(message):
    print message
    return 1

class LogConfig(dict):
    def __init__(self,config=DEFAULT_LOGCONFIG,program='deckadance'):
        self.config = config
        self.program = program
        logdir = os.path.join(os.getenv('HOME'),'.deckadance')
        if not os.path.isdir(logdir):
            os.makedirs(logdir)
        for name in ['console','modules']:
            l = logging.getLogger(name)
            h = logging.StreamHandler()
            h.setFormatter(logging.Formatter(config['logformat']))
            l.addHandler(h)
            self[name] = l

    def __setattr__(self,attr,value):
        object.__setattr__(self,attr,value)
        if attr == 'level':
            for name,logger in self.items():
                logger.setLevel(self.level)

def prepare(argv):
    """
    Prepare common script defaults:
    - call setproctitle
    - initialize optparse parser with default flags
    
    Returns (MusaConfig,OptionParser) objects to be used by caller
    """
    setproctitle('%s %s' % (MYNAME,' '.join(argv[1:])))
    signal.signal(signal.SIGINT, Interrupted) 

    parser = OptionParser()
    parser.add_option('-v','--verbose',dest='verbose',action='store_true',help='Show verbose messages')
    parser.add_option('-d','--debug',dest='debug',action='store_true',help='Show debug messages')
    return parser

def initialize(parser):
    """
    Call parse_args for parse, check for default logging flags and parse 
    command line arguments to a dictionary {'albums':list,'songs':list}

    Returns:
        opts: optparse parsed options
        args: optparse parsed arguments
        targets: processed targets as dictionary
    """
    (opts,args) = parser.parse_args()

    loggers = LogConfig()
    log = logging.getLogger('console')
    try:
        if opts.verbose:
            loggers.level = logging.INFO
        if opts.debug:
            loggers.level = logging.DEBUG
    except ValueError:
        pass
    return (opts,args)


