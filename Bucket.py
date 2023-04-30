# Bucket Class
import pyshark
from Counter import *

TCP_COUNTER_TYPE = ("csack", "c0", "cd", "cf", "s0", "sd", "sf", "ca1", "ca2", "ca3", "sa1", "sa2", "sa3")
UDP_COUNTER_TYPE = ("ca1", "ca2", "ca3", "ca4", "sa1", "sa2", "sa3", "sa4")
TCP_FEATURES = ("csack" , "cpp", "spp", "spdsd", "spdsp")
UDP_FEATURES = ("ca1" , "ca2" , "spdsd", "spdsp")

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


    def InsertTCPServer(self, pkt):
        self.tcpCts["s0"] += Ct_s0(pkt)
        self.tcpCts["sd"] += Ct_sd(pkt)
        self.tcpCts["sf"] += Ct_sf(pkt)
        self.tcpCts["sa1"] += Ct_ca(pkt, 0, 83)
        self.tcpCts["sa2"] += Ct_ca(pkt, 83, 375)
        self.tcpCts["sa3"] += Ct_ca(pkt, 375, 1100)


    def InsertTCPClient(self, pkt):
        self.tcpCts["csack"] += Ct_sack(pkt)
        self.tcpCts["c0"] += Ct_c0(pkt)
        self.tcpCts["cd"] += Ct_cd(pkt)
        self.tcpCts["cf"] += Ct_cf(pkt)
        self.tcpCts["ca1"] += Ct_ca(pkt, 0, 83)
        self.tcpCts["ca2"] += Ct_ca(pkt, 83, 375)
        self.tcpCts["ca3"] += Ct_ca(pkt, 375, 1100)
    

    def InsertUDPServer(self, pkt, d=20):
        ret = Cu_payloadSz(pkt, d)
        if ret == 1:
            self.udpCts["sa1"] += 1
        elif ret == 2:
            self.udpCts["sa2"] += 1
        elif ret == 3:
            self.udpCts["sa3"] += 1
        elif ret == 4:
            self.udpCts["sa4"] += 1


    def InsertUDPClient(self, pkt, d=20):
        ret = Cu_payloadSz(pkt, d)
        if ret == 1:
            self.udpCts["ca1"] += 1
        elif ret == 2:
            self.udpCts["ca2"] += 1
        elif ret == 3:
            self.udpCts["ca3"] += 1
        elif ret == 4:
            self.udpCts["ca4"] += 1

    def GetCtVal(self, protocol, attr):
        if protocol == "udp":
            return self.udpCts[attr]
        elif protocol == "tcp":
            return self.tcpCts[attr]
