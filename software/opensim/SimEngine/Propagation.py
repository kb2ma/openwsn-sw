#!/usr/bin/python

import logging

class NullLogHandler(logging.Handler):
    def emit(self, record):
        pass
    
class Propagation(object):
    '''
    \brief The propagation model of the engine.
    '''
    
    def __init__(self,engine):
        
        # store params
        self.engine               = engine
        
        # local variables
        
        # logging
        self.log                  = logging.getLogger('Propagation')
        self.log.setLevel(logging.DEBUG)
        self.log.addHandler(NullLogHandler())
    
    #======================== public ==========================================
    
    def txStart(self,moteId,packet,channel):
    
        # log
        self.log.info('txStart from {0} on channel {1}, {2} bytes'.format(
                             moteId,
                             channel,
                             len(packet)))
        
        # TODO: calculate rssi
        
        # indicate to each mote
        for i in range(self.engine.getNumMotes()):
            motehandler = self.engine.getMoteHandler(i)
            if motehandler.getId()!=moteId:
                motehandler.bspRadio.indicateTxStart(moteId,packet,channel)
    
    def txEnd(self,moteId):
        
        # log
        self.log.info('txStop from {0}'.format(moteId))
    
        # indicate to each mote
        for i in range(self.engine.getNumMotes()):
            motehandler = self.engine.getMoteHandler(i)
            if motehandler.getId()!=moteId:
                motehandler.bspRadio.indicateTxEnd(moteId)
    
    #======================== private =========================================
    
    #======================== helpers =========================================
    