#!/usr/bin/env python

import os
import sys
temp_path = sys.path[0]
sys.path.insert(0, os.path.join(temp_path, '..'))
sys.path.insert(0, os.path.join(temp_path, '..', '..'))

import logging
import logging.handlers
import json

import pytest

import RPL
from   openType import typeUtils as u

#============================ logging =========================================

LOGFILE_NAME = 'test_sourceRoute.log'

import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
log = logging.getLogger('test_sourceRoute')
log.setLevel(logging.ERROR)
log.addHandler(NullHandler())

logHandler = logging.handlers.RotatingFileHandler(LOGFILE_NAME,
                                                  backupCount=5,
                                                  mode='w')
logHandler.setFormatter(logging.Formatter("%(asctime)s [%(name)s:%(levelname)s] %(message)s"))
for loggerName in ['test_sourceRoute',
                   'RPL',]:
    temp = logging.getLogger(loggerName)
    temp.setLevel(logging.DEBUG)
    temp.addHandler(logHandler)
    
#============================ defines =========================================

MOTE_A = [0xaa]*8
MOTE_B = [0xbb]*8
MOTE_C = [0xcc]*8
MOTE_D = [0xdd]*8

#============================ fixtures ========================================

EXPECTEDSOURCEROUTE = [
    json.dumps((MOTE_B, [MOTE_B,MOTE_A])),
    json.dumps((MOTE_C, [MOTE_C,MOTE_B,MOTE_A])),
    json.dumps((MOTE_D, [MOTE_D,MOTE_C,MOTE_B,MOTE_A])),
]

@pytest.fixture(params=EXPECTEDSOURCEROUTE)
def expectedSourceRoute(request):
    return request.param

#============================ helpers =========================================


#============================ tests ===========================================

def test_sourceRoute(expectedSourceRoute):
    '''
    This tests the following topology
    
    MOTE_A <- MOTE_B <- MOTE_C <- MOTE_D
    '''
    
    rpl = RPL.RPL()
    
    rpl.parents = {
        tuple(MOTE_B): [MOTE_A],
        tuple(MOTE_C): [MOTE_B],
        tuple(MOTE_D): [MOTE_C],
    }
    
    expectedDestination = json.loads(expectedSourceRoute)[0]
    expectedRoute       = json.loads(expectedSourceRoute)[1]
    calculatedRoute     = rpl.getRouteTo(expectedDestination)
    
    # log
    output              = []
    output             += ['\n']
    output             += ['expectedDestination: {0}'.format(u.formatAddress(expectedDestination))]
    output             += ['expectedRoute:']
    for m in expectedRoute:
            output     += ['- {0}'.format(u.formatAddress(m))]
    output             += ['calculatedRoute:']
    for m in calculatedRoute:
            output     += ['- {0}'.format(u.formatAddress(m))]
    output               = '\n'.join(output)
    log.debug(output)
    
    assert calculatedRoute==expectedRoute
