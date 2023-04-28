from BucketTable import BucketTable
from ReadFile import *




def test7():
    path = 'target_files.txt'
    target = GetListOfpcapPaths(path)
    for pcap in target:
        print(pcap)


def main():
    tcp = "./tcp.csv"
    udp = "./udp.csv"
    path = 'target_files.txt'

    t = BucketTable(row=5, bktSize=10)
    t.SetTargetIP("192.168.1.11")
    t.SetCSVPath(tcp, udp)

    target = GetListOfpcapPaths(path)
    for pcap in target:
        print(f">>>>> Start With {pcap}<<<<<")
        t.ReadPCAP(pcap)
        print(f">>>>> DONE With {pcap}<<<<<\n")

if __name__ == '__main__':
    main()
