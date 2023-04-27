from Bucket import Bucket
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

    def ReadPCAP(self, path):
        analyzer = PacketAnalyzer(TSharkPATH)
        capture = analyzer.OpenPCAP(path)
        # Insert
        for packet in capture:
            self.InsertToAllRows(packet)

        capture.close()

    def Insert(self, packet, row, col):
        bucket = self.table[row][col]
        if "TCP" in packet:
            bucket.InsertTCP(packet)
        elif "UDP" in packet:
            bucket.InsertUDP(packet)
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




