from BucketTable import BucketTable
from BucketTable import calculateSpdSD

from Bucket import Bucket

# cf test
def test():
    pcap_file = 'Wireshark_802_11.pcap'
    t = BucketTable(row=5, bktSize=10)
    t.SetServerAndClientIP(ipc="128.119.101.5", ips="192.168.1.109")
    t.ReadPCAP(pcap_file)

    try:
        r = 2
        for c in range(10):
            print(t.table[r][c].tcpCts["cf"])
    except:
        print("test faild")


# csack test
def test2():
    pcap_file = 'sample.pcap'
    t = BucketTable(row=5, bktSize=10)
    t.SetServerAndClientIP(ipc="64.31.35.242", ips="192.168.1.109")
    t.ReadPCAP(pcap_file, filter="tcp && tcp.options.sack.count == 1")

    print(">>> ")
    try:
        r = 2
        for c in range(10):
            print(t.table[r][c].tcpCts["csack"])
    except:
        print("test faild")

# cf test
def test3():
    pcap_file = 'Wireshark_802_11.pcap'
    file2 = 'sample.pcap'
    t = BucketTable(row=5, bktSize=10)
    t.SetServerAndClientIP(ipc="10.26.85.14", ips="192.168.1.109")
    t.ReadPCAP(file2, filter="((tcp.len < 83) && (ip.src == 10.26.85.14)) && (ip.dst == 64.31.35.242)")

    try:
        r = 2
        for c in range(10):
            print(t.table[r][c].tcpCts["ca1"], " ", t.table[r][c].tcpCts["ca2"], t.table[r][c].tcpCts["ca3"])
    except:
        print("test faild")


def test4():
    pcap_file = 'Wireshark_802_11.pcap'
    file2 = 'sample.pcap'
    t = BucketTable(row=5, bktSize=10)
    t.SetServerAndClientIP(ipc="128.119.245.12", ips="192.168.1.109")
    t.ReadPCAP(pcap_file)

    try:
        r = 2
        for c in range(10):
            print(  t.table[r][c].tcpCts["ca1"], " ",
                    t.table[r][c].tcpCts["ca2"], " ",
                    t.table[r][c].tcpCts["ca3"] )
    except:
        print("test faild")


# Test saturation event
def test5():
    pcap_file = 'Wireshark_802_11.pcap'
    file2 = 'sample.pcap'
    t = BucketTable(row=5, bktSize=10)
    t.SetServerAndClientIP(ips="23.43.124.211", ipc="10.26.85.14")
    t.ReadPCAP(file2)

def test6():
    print(calculateSpdSD(366, [0, 83, 375, 1100]))



if __name__ == '__main__':
    test5()
