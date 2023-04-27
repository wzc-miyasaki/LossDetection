from Bucket import *
import hashlib
import uuid
from PacketAnalyzer import *


def GetSrcKey(pkt):
    srcIP = pkt.ip.src
    srcPort = ""
    if hasattr(pkt, 'udp'):
        srcPort = str(pkt.udp.srcport)
    elif hasattr(pkt, 'tcp'):
        srcPort = str(pkt.tcp.srcport)
    return srcIP, srcPort


class BucketTable:

    def __init__(self, row, bktSize):
        self.rowNumber = row
        self.colNumber = bktSize
        self.hashList = []
        self.table = []
        self.saturationFlag = False
        self.hashAlgOption = [hashlib.sha1, hashlib.sha256, hashlib.md5]
        self.servip = ""
        self.clientip = ""

        self.InitHashFunctions(row)
        self.InitTable(row, bktSize)

    def InitHashFunctions(self, sz):
        for i in range(sz):
            hash_key = str(uuid.uuid4())    # generate unique hash_key value
            self.hashList.append(hash_key)

    def hashSrcKey(self, src_key, row):
        # Pick a hash algorithm
        hashAlg = self.hashAlgOption[row % 3]

        # hash operation
        ip, port = src_key
        combine = ip + port
        hash_code = hashAlg(combine.encode()).digest()
        columIdx = int.from_bytes(hash_code, byteorder='little') %  self.colNumber
        return columIdx

    def InitTable(self, r, c):
        for i in range(r):
            self.table.append([])
            for j in range(c):
                self.table[i].append(Bucket())

    def SetServerAndClientIP(self, ips, ipc):
        if ips == ipc:
            print("[Error]:  server & client IP cannot be same")
            return
        self.servip = ips
        self.clientip = ipc

    def ReadPCAP(self, path, filter=""):
        if self.servip == "" or self.clientip == "":
            print("[Error] Server IP & Client IP address is not set up!\n\n")
            return

        analyzer = PacketAnalyzer(TSharkPATH)
        analyzer.SetFilter(filter)
        capture = analyzer.OpenPCAP(path)

        # Insert each packet to the table
        for packet in capture:
            self.InsertToAllRows(packet)

        capture.close()

    def Insert(self, packet, row, col):
        bucket = self.table[row][col]

        if "TCP" in packet:
            if self.IsServer(packet):
                bucket.InsertTCPServer(packet)
            elif self.IsClient(packet):
                bucket.InsertTCPClient(packet)

        elif "UDP" in packet:
            if self.IsServer(packet):
                bucket.InsertUDPServer(packet)
            elif self.IsClient(packet):
                bucket.InsertUDPClient(packet)
        else:
            return

    def InsertToAllRows(self, pkt):
        hasIp = hasattr(pkt, 'ip')
        hasTcp = hasattr(pkt, 'tcp')
        hasUdp = hasattr(pkt, 'udp')
        canInsert = False

        if (hasIp and hasTcp) or (hasIp and hasUdp):
            canInsert = True

        if(canInsert):
            for row in range(self.rowNumber):
                key = GetSrcKey(pkt)
                col = self.hashSrcKey(key, row)
                self.Insert(pkt, row, col)

    def IsClient(self, pkt):
        return pkt.ip.src == self.clientip

    def IsServer(self, pkt):
        return pkt.ip.src == self.servip


