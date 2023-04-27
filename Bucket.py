# Bucket Class
import pyshark
from Counter import *

TCP_COUNTER_TYPE = ("csack", "c0", "cd", "cf", "s0", "sd", "sf", "ca1", "ca2", "ca3", "sa1", "sa2", "sa3")
UDP_COUNTER_TYPE = ("ca1", "ca2", "ca3", "ca4", "sa1", "sa2", "sa3", "sa4")



class Bucket:
    def __init__(self):
        self.tcpCts = {}
        self.udpCts = {}
        self.ResetCounter()


    def _InitTCPcounters(self):
        for name in TCP_COUNTER_TYPE:
            self.tcpCts[name] = 0

    def _InitUDPcounters(self):
        for name in UDP_COUNTER_TYPE:
            self.udpCts[name] = 0

    def ResetCounter(self):
        self._InitTCPcounters()
        self._InitUDPcounters()


    def InsertTCP(self, pkt):

        self.tcpCts["c0"] += Ct_c0(pkt)
        return

    def InsertUDP(self, pkt):
        # print("udp")
        return