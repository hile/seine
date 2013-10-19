#!/usr/bin/env python
"""
Modified Pinger class based on pyip package ping.py. Modified to give exact
times as floats, to support intervals and source address changing.

Author: Ilkka Tuohela, hile@iki.fi

Original ping.py header and license:

pyip is a Python package offering assembling/disassembling of raw ip packet
including ip, udp, and icmp. Also it includes 2 utilities based on raw ip,
traceroute and ping.

pyip is released under PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2, and is
a project inspired by 'ping' written by Jeremy Hylton.

Author: Kenneth Jiang, kenneth.jiang@gmail.com

"""

import os
import sys
import time
import string
import decimal
import icmp
import ip
import socket
import select

MAX_PACKETS = 1000
PAYLOAD = 'seine pinger'

class PingError(Exception):
    pass

class PingSocket(object):
    """
    Wrapper for socket to use with ICMP PING packets.

    If source address is given, the requests are sent using given
    address. The address must be configured on a interface.
    """
    def __init__(self, target, source=None):
        self.target = (socket.gethostbyname(target), 0)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.socket.setblocking(1)

        if source is not None:
            try:
                self.socket.bind((source, socket.IPPROTO_ICMP))
            except socket.error, (ecode, emsg):
                raise PingError('Error binding to source address %s: %s' % (source, emsg))

    def sendto(self, packet):
        try:
            self.socket.sendto(packet, self.target)
        except socket.error, (ecode, emsg):
            raise PingError(emsg)

    def recvfrom(self, maxbytes):
        return self.socket.recvfrom(maxbytes)

class Pinger(object):
    """
    Pinger instance.

    If source address is not given, default chosen by OS is used.

    Timeout is given as milliseconds, default value is 1000.
    Packet interval is given as milliseconds, default value is 1000.
    """

    def __init__(self, target, source=None, timeout=1000, interval=1000):
        self.socket = PingSocket(target, source)
        self.timeout = int(timeout)
        self.interval = int(interval)
        self.pid = os.getpid()
        self.__reset_counters()

    def __reset_counters(self):
        """
        Internal function to reset result counters between ping() calls
        """
        self.last = 0
        self.sent = 0
        self.times = {}
        self.deltas = []
        self.timed_out = []

    def __send_packet(self):
        """
        Internal function to send icmp ECHO packet to target address.
        """
        buf = icmp.assemble(icmp.Echo(id=self.pid, seq=self.sent, data=PAYLOAD))
        self.times[self.sent] = time.time()
        self.sent += 1
        self.socket.sendto(buf)

    def __recv_packet(self, pkt, when, timeout):
        """
        Internal function to process a received response packet
        """
        try:
            sent = self.times[pkt.get_seq()]
        except KeyError:
            print 'Invalid packet sequence number: %s' % pkt.get_seq()
            return

        if when-sent <= timeout:
            self.deltas.append(float(when-sent)*1000)
        else:
            print '%s timed out' % sent
            self.timed_out.append(sent)

    def ping(self, packets=1):
        """
        Send ping messages, as many as given with packets parameter.

        Returns a dictionary of results, may raise PingError.
        """

        try:
            packets = int(packets)
            if packets < 0 or packets > MAX_PACKETS:
                raise ValueError
        except ValueError:
            raise PingError('Invalid number of packets: %s' % packets)

        interval = float(self.interval)/1000
        timeout = float(self.timeout)/1000
        last_sent = 0
        while 1:
            now = time.time()
            if self.sent < packets and (last_sent+interval)<now:
                self.__send_packet()
                last_sent = now

            if len(self.times) == packets:
                if filter(lambda t: t+timeout>now, self.times.values())==[]:
                    break

            (rd, wt, er) = select.select([self.socket.socket], [], [], timeout)
            if not rd:
                continue
            arrival = time.time()
            try:
                (pkt, who) = self.socket.recvfrom(4096)
            except socket.error:
                continue

            reply_address = ip.disassemble(pkt)
            try:
                reply = icmp.disassemble(reply_address.data)
            except ValueError:
                print 'Invalid ICMP reply packet received'
                continue

            if reply.get_id() != self.pid:
                print 'PID in response does not match'
                continue
            self.__recv_packet(reply, arrival, timeout)

            if self.sent < packets:
                continue

            if len(self.deltas)+len(self.timed_out) == packets:
                break

        received = len(self.deltas)
        loss = (float(packets-received)/float(packets))*100

        if len(self.deltas) == 0:
            summary = {
                'min': None,
                'max': None,
                'average': None,
                'sent': packets,
                'received': len(self.deltas) + len(self.timed_out),
                'packetloss': loss
            }

        else:
            summary = {
                'min': min(self.deltas),
                'max': max(self.deltas),
                'average': reduce(lambda x, y: x+y, self.deltas) / len(self.deltas),
                'sent': packets,
                'received': received,
                'packetloss': loss
            }

        self.__reset_counters()
        return summary
