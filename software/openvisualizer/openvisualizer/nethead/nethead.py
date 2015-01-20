# Copyright (c) 2015, Ken Bannister
# All rights reserved. 
#  
# Released under the Mozilla Public License 2.0, as published at the link below.
# http://opensource.org/licenses/MPL-2.0
import logging
log = logging.getLogger('nethead')
log.setLevel(logging.ERROR)
log.addHandler(logging.NullHandler())

from   openvisualizer.eventBus import eventBusClient
from   openvisualizer.openLbr.openLbr import OpenLbr
import openvisualizer.openvisualizer_utils as u
import random
from   soscoap.message import CoapMessage, CoapOption
from   soscoap import CodeClass, MessageType, OptionType, RequestCode
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

class Nethead(eventBusClient.eventBusClient):
    '''Network monitoring entity for the DAGroot node. Required in OpenVisualizer
    since OpenWSN firmware uses the root node only as a radio bridge. So, all 
    DAGroot application messaging must originate/terminate with OpenVisualizer.
    
    When DAGroot is established, Nethead class registers with Nethead home peer 
    by sending a 'hello' message.
    '''
    
    def __init__(self):
        
        # log
        log.info('create instance')
        
        # store params
        self.stateLock            = threading.Lock()
        self.networkPrefix        = None
        self.dagRootEui64         = None
        self.lastMessageId        = random.randint(0, 0xFFFF)
        self._lastEphemeralPort   = None
        self.isRegistered         = False
         
        # initialize parent class
        eventBusClient.eventBusClient.__init__(
            self,
            name = 'OpenLBR',
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
                    self._sendHello()
                except:
                    log.exception('Failed to send hello to Nethead home')
                    
    def _recvHello_notif(self, sender, signal, data):
        '''Handles response from Nethead home to confirm registration.
        '''
        # No app payload, just remember registration
        isRegistered = True
        log.info('Received hello response')
        # Only registered for this single response, so unregister.
        self.unregister(
            sender            = self.WILDCARD,
            signal            = (
                tuple(self.networkPrefix + self.dagRootEui64),
                OpenLbr.IANA_UDP,
                self._lastEphemeralPort),
            callback          = self._recvHello_notif)
            
    def _sendHello(self):
        '''Send '/nh/lo' message to Nethead home, and prepare to wait for home's 
        response.
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
        
        self._lastEphemeralPort = random.randint(49152,65535)
        self.register(
            sender            = self.WILDCARD,
            signal            = (
                tuple(self.networkPrefix + self.dagRootEui64),
                OpenLbr.IANA_UDP,
                self._lastEphemeralPort),
            callback          = self._recvHello_notif)
        
        # write packet
        srcAddr = self.networkPrefix + self.dagRootEui64
        dstAddr = NETHEAD_HOME

        log.debug('Serializing CoAP message')
        pkt     = list(msgModule.serialize(msg))        # convert from bytearray to list
                                                        # for compatibility with OpenWSN
        pkt[:0] = self._writeUdpHeader(pkt, srcAddr, dstAddr, self._lastEphemeralPort)
        pkt[:0] = self._writeIpv6Header(pkt, srcAddr, dstAddr)
        
        self.dispatch('v6ToInternet', pkt)
        
    def _writeUdpHeader(self, payload, srcAddr, dstAddr, srcPort):
        '''Writes UDP header fields to a byte list.
        
        :returns: byte list
        '''
        hdr  = int2buf(srcPort, 2)                    # src port (ephemeral) 
                                                      # http://tools.ietf.org/html/rfc6335
        hdr += int2buf(5683, 2)                       # dest port, CoAP default
        hdr += int2buf(8+len(payload), 2)             # length

        pseudoHdr  = []
        pseudoHdr += srcAddr
        pseudoHdr += dstAddr
        pseudoHdr += int2buf(8+len(payload), 4)
        pseudoHdr += int2buf(OpenLbr.IANA_UDP, 4)
        
        hdr += u.calculateUdpChecksum(pseudoHdr, hdr, payload)  # checksum
        return hdr
        
    def _writeIpv6Header(self, payload, srcAddr, dstAddr):
        '''Writes IPv6 header fields to a byte list.
        
        :returns: byte list
        '''
        hdr  = [6<<4]                # v6 + traffic class (upper nybble)
        hdr += [0x00]*3              # traffic class (lower nybble) + flow label
                                     # default PHB; RFC 2474, sec. 4.1
                                     # no flow; RFC 2460, app. A
        hdr += payload[4:6]          # payload length
        hdr += [OpenLbr.IANA_UDP]    # next header / protocol
        hdr += [64]                  # hop limit
                                     # http://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
        hdr += srcAddr               # source
        hdr += dstAddr               # destination
        return hdr
        