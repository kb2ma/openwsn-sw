# Copyright (c) 2015, Ken Bannister
# All rights reserved. 
#  
# Released under the Mozilla Public License 2.0, as published at the link below.
# http://opensource.org/licenses/MPL-2.0
import logging
log = logging.getLogger('nethead')
log.setLevel(logging.ERROR)
log.addHandler(logging.NullHandler())

import json
from   openvisualizer.eventBus import eventBusClient
from   openvisualizer.nethead.messenger import Messenger
from   openvisualizer.openLbr.openLbr import OpenLbr
import openvisualizer.openvisualizer_utils as u
import random
from   soscoap.message import CoapMessage, CoapOption
from   soscoap import CodeClass, MediaType, MessageType, OptionType, RequestCode
from   soscoap import message as msgModule
import threading

#============================ parameters ======================================
NETHEAD_HOME = [0xfd, 0xc8, 0x70, 0xa6, 0x51, 0x1c, 0x00, 0x00,
                0x22, 0x1a, 0x06, 0xff, 0xfe, 0x03, 0xca, 0xf6]
'''Address for nethead home peer/server'''
    
def int2buf(intVal, length):
    '''
    Creates a buffer with the hex values that represent the provided integer.
    
    This method can/should be moved to the openvisualizer_utils module.
    
    :param intVal:    [in] integer to convert
    :param length:    [in] required buffer length
    :returns:         Big endian list of integer bytes
    '''
    buf = [0] * length
    pos = length - 1
    while intVal > 0:
        if pos < 0:
            raise IndexError('buffer too short ({0})'.format(length))
        buf[pos] = intVal & 0xFF
        intVal   = intVal >> 8
        pos      = pos - 1
    return buf
    
def buf2hex(addr):
    '''
    Converts a byte list into a string of hex chars. For example:

       [0xab,0xcd,0xef,0x00] -> 'abcdef00'
    
    :param addr: [in] Byte list to convert
    
    :returns: String with the contents of addr.
    '''
    return ''.join(["%02x" % b for b in addr])


class Nethead(eventBusClient.eventBusClient):
    '''Network monitoring entity for the DAGroot node. Required in OpenVisualizer
    since OpenWSN firmware uses the root node only as a radio bridge. So, all 
    DAGroot application messaging must originate/terminate with OpenVisualizer.
    
    When DAGroot is established, Nethead class registers with Nethead home peer 
    by sending a 'hello' message. When Nethead home confirms the registration,
    begins sending RSS reports once per minute.
    '''
    
    def __init__(self, ovApp):
        '''Initialize
        
        :param ovApp:  [in] OpenVisualizer application instance; required to retrieve
                            mote state
        '''
        
        # log
        log.info('create instance')
        
        # store params
        self.stateLock            = threading.Lock()
        self.ovApp                = ovApp
        self.networkPrefix        = None
        self.dagRootEui64         = None
        self.lastMessageId        = random.randint(0, 0xFFFF)
        self._lastEphemeralPort   = None
        self.isRegistered         = False
        self.timer                = None
        
        self.RSS_INTERVAL         = 60
         
        # initialize parent class
        eventBusClient.eventBusClient.__init__(
            self,
            name = 'Nethead',
            registrations =  [
                {
                    'sender'   : self.WILDCARD,
                    'signal'   : 'networkPrefix', #signal once a prefix is set.
                    'callback' : self._setPrefix_notif
                },
                {
                    'sender'   : self.WILDCARD,
                    'signal'   : 'infoDagRoot', #signal once a dagroot id is received
                    'callback' : self._infoDagRoot_notif, 
                },
            ]
        )

    
    def _setPrefix_notif(self, sender, signal, data):
        '''Record the network prefix.
        '''
        with self.stateLock:
            self.networkPrefix = data  
            log.info('Set network prefix {0}'.format(u.formatIPv6Addr(data)))
            
    def _infoDagRoot_notif(self, sender, signal, data):
        '''Record the DAGroot's EUI64 address.
        '''
        if data['isDAGroot']==1:
            with self.stateLock:
                self.dagRootEui64 = data['eui64'][:]
            if self.networkPrefix:
                log.info('Sending hello message to Nethead home')
                try:
                    messenger = Messenger(self.networkPrefix + self.dagRootEui64)
                    messenger.send(self._createHelloMessage(), 
                                   NETHEAD_HOME,
                                   lambda: self._recvHello_notif())
                except:
                    log.exception('Failed to send hello message to Nethead home')
                    
    def _recvHello_notif(self):
        '''Handles response from Nethead home to confirm registration, and schedules
        RSS messaging.
        '''
        # No app payload, just remember registration
        isRegistered = True
        log.info('Received hello reply')

        self.timer = threading.Timer(self.RSS_INTERVAL, self._sendRssMessage)
        self.timer.start()
                    
    def _recvRss_notif(self):
        '''Handles response from Nethead home to confirm posting RSS readings, and
        schedules the next message.
        '''
        log.info('Received rss reply')

        self.timer = threading.Timer(self.RSS_INTERVAL, self._sendRssMessage)
        self.timer.start()
        
    def _sendRssMessage(self):
        '''Creates and sends '/nh/rss' message to Nethead home. Queries ??? for
        latest RSS value.
        '''
        log.info('Sending rss message to Nethead home')
        try:
            messenger = Messenger(self.networkPrefix + self.dagRootEui64)
            messenger.send(self._createRssMessage(), 
                           NETHEAD_HOME,
                           lambda: self._recvRss_notif())
        except:
            log.exception('Failed to send RSS message to Nethead home')
            # Maybe better luck next time
            self.timer = threading.Timer(self.RSS_INTERVAL, self._sendRssMessage)
            self.timer.start()
            
    def _createHelloMessage(self):
        '''Creates '/nh/lo' message for Nethead home.
        '''
        msg             = CoapMessage()
        # header
        msg.tokenLength = 2
        msg.token       = int2buf(random.randint(0,0xFFFF), 2)
        msg.codeClass   = CodeClass.Request
        msg.codeDetail  = RequestCode.POST
        msg.messageType = MessageType.NON
        with self.stateLock:
            msg.messageId      = self.lastMessageId+1 if self.lastMessageId < 0xFFFF else 0
            self.lastMessageId = msg.messageId

        # options, no payload
        msg.options = [
            CoapOption(OptionType.UriPath, 'nh'),
            CoapOption(OptionType.UriPath, 'lo')
        ]
        return msg
            
    def _createRssMessage(self):
        '''Creates '/nh/rss' message for Nethead home.
        '''
        msg             = CoapMessage()
        # header
        msg.tokenLength = 2
        msg.token       = int2buf(random.randint(0,0xFFFF), 2)
        msg.codeClass   = CodeClass.Request
        msg.codeDetail  = RequestCode.POST
        msg.messageType = MessageType.NON
        with self.stateLock:
            msg.messageId      = self.lastMessageId+1 if self.lastMessageId < 0xFFFF else 0
            self.lastMessageId = msg.messageId

        # options
        msg.options = [
            CoapOption(OptionType.UriPath, 'nh'),
            CoapOption(OptionType.UriPath, 'rss'),
            CoapOption(OptionType.ContentFormat, MediaType.Json)
        ]
        
        # Payload of latest RSS reading
        rssValues = self._readRss()
        if rssValues:
            msg.payloadStr(json.dumps(rssValues))
            log.debug('Added neighbors to RSS payload')
        else:
            log.warn('No neighbors found for RSS message')
            raise KeyError
                
        return msg
        
    def _readRss(self):
        '''Reads RSS values from moteState module for DAGroot node.
        
        :return: Dictionary with key of last two bytes of neighbor address as 
                 a hex string, with format 'xxxx'; and value of the RSS reading.
        '''
        dagRoot16 = buf2hex(self.dagRootEui64[-2:])
        rootState = self.ovApp.getMoteState(dagRoot16)
        rssValues = {}
        if rootState:
            log.debug('Found moteState for dagRoot {0}'.format(dagRoot16))
            nbrTable = rootState.getStateElem(rootState.ST_NEIGHBORS)
            if not nbrTable:
                log.warn('Can\'t find nbrTable')
                return
                
            rowIndex = 0
            for row in nbrTable.data:
                nbrAddr = row.data[0]['addr']
                if nbrAddr.addr:
                    nbrRssi = row.data[0]['rssi']
                    if nbrRssi.rssi:
                        # Only use last two bytes of address
                        rssValues[buf2hex(nbrAddr.addr[-2:])] = nbrRssi.rssi
                        log.debug('Found RSS value at row {0}; nbrAddr: {1}'.format(rowIndex, 
                                                                                    u.formatAddr(nbrAddr.addr)))
                    else:
                        log.debug('Can\'t find nbrRssi at row {0}'.format(rowIndex))
                rowIndex = rowIndex + 1
        else:
            log.error('Can\'t find moteState for {0}'.format(dagRoot16))
            raise KeyError

        return rssValues