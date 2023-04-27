from BucketTable import BucketTable
from Bucket import Bucket

def test():
    pcap_file = 'Wireshark_802_11.pcap'
    t = BucketTable(row=5, bktSize=10)
    t.ReadPCAP(pcap_file)

    print(t.table[0][0].tcpCts["c0"])
    print(t.table[0][1].tcpCts["c0"])
    print(t.table[0][2].tcpCts["c0"])


if __name__ == '__main__':
    test()
