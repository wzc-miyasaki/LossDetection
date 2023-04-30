from Bucket import *
import hashlib
import uuid
from Counter import UpdateMin
from PacketAnalyzer import *
import time
from ReadFile import *
import datetime

def GetSrcKey(pkt):
    srcIP = pkt.ip.src
    srcPort = ""
    if hasattr(pkt, 'udp'):
        srcPort = str(pkt.udp.srcport)
    elif hasattr(pkt, 'tcp'):
        srcPort = str(pkt.tcp.srcport)
    return srcIP, srcPort

def calculateSpdSD(payloadSz , interval):
    a0 = interval[0]
    a1 = interval[1]
    a2 = interval[2]
    a3 = interval[3]
    v1 = max(0, payloadSz - a0) #100
    v2 = max(0, payloadSz - a1) #17
    v3 = max(0, payloadSz - a2) #0
    v4 = max(0, payloadSz - a3) #0

    res = []
    res.append(min(v1, a1-a0))
    res.append(min(v2, a2-a1))
    res.append(min(v3, a3-a2))
    res.append(v4)
    return res





class BucketTable:

    def __init__(self, row, bktSize):
        self.rowNumber = row
        self.colNumber = bktSize
        self.hashList = []
        self.table = []
        self.hashAlgOption = [hashlib.sha1, hashlib.sha256, hashlib.md5]
        self.target_ip = ""
        self.pktCountC = 0  # client packet number
        self.pktCountS = 0  # server packet number
        self.pktTotal = 0
        self.sampleInterval = 1/16.0
        self.prevSatTime = None
        self.diffT = 0.0
        self.last_ten_thousand_time = None
        self.tcp_csv_file = "tcp.csv"
        self.udp_csv_file = "udp.csv"

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

    def SetTargetIP(self, ip):
        self.target_ip = ip

    def SetCSVPath(self, tcp, udp):
        self.tcp_csv_file = tcp
        self.udp_csv_file = udp

    def ReadPCAP(self, path, filter=""):
        if self.target_ip == "":
            print("target IP is not set")
            return

        analyzer = PacketAnalyzer(TSharkPATH)
        analyzer.SetFilter(filter)
        capture = analyzer.OpenPCAP(path)

        # Insert each packet to the table
        for packet in capture:
            self.InsertToAllRows(packet)
            self.pktTotal += 1
            self.AnnounceReadingProgress()
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
            if self.IsServer(pkt):
                self.pktCountS += 1
            elif self.IsClient(pkt):
                self.pktCountC += 1

        if canInsert:
            positions = []

            # Insert
            for row in range(self.rowNumber):
                key = GetSrcKey(pkt)
                col = self.hashSrcKey(key, row)
                self.Insert(pkt, row, col)
                positions.append((row, col))

            # Saturation Check
            saturated = False
            minCtList = None
            if hasTcp:
                minCtList = self.Query(positions, "tcp")
                saturated = (minCtList["c0"] + minCtList["cd"] + minCtList["s0"] + minCtList["sd"]) >= 100
            elif hasUdp:
                minCtList = self.Query(positions, "udp")
                saturated = sum(minCtList.values()) >= 100

            if saturated:
                # Clear Bucket
                self.ResetBkt(positions)

                # Update saturation time difference
                if self.prevSatTime is None:
                    self.prevSatTime = time.time()
                else:
                    currSatTime = time.time()
                    elapsedTime = currSatTime - self.prevSatTime    # seconds
                    self.prevSatTime = currSatTime
                    self.diffT = elapsedTime

                # feature extraction
                if not is_zero(self.diffT) and minCtList is not None:
                    features = self.ExtractFeatures(pkt, minCtList)
                    if hasTcp :
                        writeExcel(features , self.tcp_csv_file)
                    elif hasUdp :
                        writeExcel(features , self.udp_csv_file)


    def ResetBkt(self, positions):
        for r, c in positions:
            self.table[r][c].ResetCounter()


    def IsClient(self, pkt):
        return pkt.ip.src == self.target_ip

    def IsServer(self, pkt):
        return pkt.ip.dst == self.target_ip


    def Query(self, positions, protocol):
        res = {}
        if protocol == "tcp":
            res = {key : -1 for key in TCP_COUNTER_TYPE}
            for r, c in positions:
                bkt = self.table[r][c]
                for attr in TCP_COUNTER_TYPE:
                    res[attr] = UpdateMin(res[attr], bkt.GetCtVal(protocol, attr))


        elif protocol == "udp":
            res = {key : -1 for key in UDP_COUNTER_TYPE}
            for r, c in positions:
                bkt = self.table[r][c]
                for attr in UDP_COUNTER_TYPE:
                    res[attr] = UpdateMin(res[attr], bkt.GetCtVal(protocol, attr))
        return res


    def ExtractFeatures(self, pkt, counters):
        res = {}
        if "TCP" in pkt:
            res = self.ExtractTCPFeature(counters, pkt)
        elif "udp" in pkt:
            res = self.ExtractUDPFeature(counters, pkt)

        return res

    def ExtractTCPFeature(self, ctValueList, pkt):
        res = {}
        for attr in TCP_FEATURES:
            res[attr] = 0.0
        res["csack"] = ctValueList["csack"]
        res["cpp"] = self.pktCountC / self.pktTotal
        res["spp"] = self.pktCountS / self.pktTotal

        # spdSP:
        a = (ctValueList["sa1"] + ctValueList["sa2"] + ctValueList["sa3"]) * self.sampleInterval
        res["spdsp"] = a / self.diffT

        # spdSD
        a = 0
        if hasattr(pkt.tcp, "payload"):
            payloadSz = len(pkt.tcp.payload)
            tmp = calculateSpdSD(payloadSz, [0, 83, 375, 1100])
            for i in tmp:
                a += i * self.sampleInterval
        res["spdsd"] = a / self.diffT

        return res

    def ExtractUDPFeature(self, ctValueList, pkt, d=20):
        res = {}
        for attr in UDP_FEATURES:
            res[attr] = 0.0
        res["ca1"] = ctValueList["ca1"] / self.pktTotal
        res["ca2"] = ctValueList["ca2"] / self.pktTotal

        # spdSP:
        a = (ctValueList["sa1"] + ctValueList["sa2"] + ctValueList["sa3"] + ctValueList["sa4"]) * self.sampleInterval
        res["spdsp"] = a / self.diffT

        # spdSD
        a = 0
        if hasattr(pkt.udp, "payload"):
            sz = len(pkt.udp.payload)
            tmp = calculateSpdSD(sz, [0, d, 140, 1100])
            for i in tmp:
                a += i * self.sampleInterval
        res["spdsd"] = a / self.diffT

        return res

    def AnnounceReadingProgress(self):
        # Get the current time
        current_time = datetime.datetime.now()

        # Format and print the current time
        formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")

        if self.pktTotal % 10000 == 0 :
            print(f"\t\t>>> >>> >>> {self.pktTotal} packets has been read so far [{formatted_time } s]")
