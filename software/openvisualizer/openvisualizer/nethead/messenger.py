# Copyright (c) 2015, Ken Bannister
# All rights reserved. 
#  
# Released under the Mozilla Public License 2.0, as published at the link below.
# http://opensource.org/licenses/MPL-2.0
import logging
log = logging.getLogger('messenger')
log.setLevel(logging.ERROR)
log.addHandler(logging.NullHandler())

import nethead
from   openvisualizer.eventBus import eventBusClient
from   openvisualizer.openLbr.openLbr import OpenLbr
import openvisualizer.openvisualizer_utils as u
import random
from   soscoap import message as msgModule
import threading

#============================ parameters ======================================

class Messenger(eventBusClient.eventBusClient):
    '''Sends and receives nethead-generated CoAP messages to external IPv6 hosts 
    via the event bus. Supports at most a single outstanding message.
    '''
    def __init__(self, sourceAddress):
        
        # log
        log.info('create instance')
        
        # store params
        self.stateLock            = threading.Lock()
        self.sourceAddress        = sourceAddress
        self._lastDestination     = None
        self._lastEphemeralPort   = None
        self._replyCallback       = None

        # initialize parent class
        eventBusClient.eventBusClient.__init__(
            self,
            name = 'Messenger',
            registrations =  []
        )

                    
    def _receive_notif(self, sender, signal, data):
        '''Notifies client of message receipt via this messenger's _replyCallback
        function.
        '''
        log.info('Received response')
        # Only registered for this single response, so unregister.
        self.unregister(
            sender            = self.WILDCARD,
            signal            = (
                tuple(self.sourceAddress),
                OpenLbr.IANA_UDP,
                self._lastEphemeralPort),
            callback          = self._receive_notif)
        self._replyCallback()
            
    def send(self, message, dstAddr, callback):
        '''Sends the provided message to Nethead home. Will call the provided
        callback function on receipt of message reply. 
        
        :param message: CoapMessage to send
        :param dstAddr: List of integer bytes for the destination address
        :param callback: Function to call on reply
        '''
        self._lastEphemeralPort = random.randint(49152,65535)
        self._replyCallback     = callback
        self.register(
            sender            = self.WILDCARD,
            signal            = (
                tuple(self.sourceAddress),
                OpenLbr.IANA_UDP,
                self._lastEphemeralPort),
            callback          = self._receive_notif)
        
        # write packet
        log.debug('Serializing CoAP message')
        pkt     = list(msgModule.serialize(message))    # convert from bytearray to list
                                                        # for compatibility with OpenWSN
        pkt[:0] = self._writeUdpHeader(pkt, self.sourceAddress, dstAddr, self._lastEphemeralPort)
        pkt[:0] = self._writeIpv6Header(pkt, self.sourceAddress, dstAddr)
        
        self.dispatch('v6ToInternet', pkt)
        
    def _writeUdpHeader(self, payload, srcAddr, dstAddr, srcPort):
        '''Writes UDP header fields to a byte list.
        
        :returns: byte list
        '''
        hdr  = nethead.int2buf(srcPort, 2)            # src port (ephemeral) 
                                                      # http://tools.ietf.org/html/rfc6335
        hdr += nethead.int2buf(5683, 2)               # dest port, CoAP default
        hdr += nethead.int2buf(8+len(payload), 2)     # length

        pseudoHdr  = []
        pseudoHdr += srcAddr
        pseudoHdr += dstAddr
        pseudoHdr += nethead.int2buf(8+len(payload), 4)
        pseudoHdr += nethead.int2buf(OpenLbr.IANA_UDP, 4)
        
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
        