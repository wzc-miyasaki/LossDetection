from BucketTable import BucketTable
from ReadFile import *




def test7():
    path = 'target_files.txt'
    target = GetListOfpcapPaths(path)
    for pcap in target:
        print(pcap)


def main():
    tcp = "./tcp_low_3.csv"
    udp = "./udp_low_3.csv"
    path = 'target_files.txt'
    yourIP = "192.169.1.1"

    target = GetListOfpcapPaths(path)

    # for p in target:
    #     print(GetRidoffExtension(p)[9:])

    try:
        for pcap in target:
            print(f">>>>> Start With {pcap}<<<<<")
            filename = GetRidoffExtension(pcap)[9:]
            tcp = filename + '.csv'
            udp = filename + '.csv'
            print(f"\t\tTCP CSV file name : {tcp}")
            print(f"\t\tUDP CSV file name : {udp}\n")

            t = BucketTable(row=5, bktSize=10)
            t.SetTargetIP(yourIP)
            t.SetCSVPath(tcp, udp)
            t.ReadPCAP(pcap)

            print(f">>>>> DONE With {pcap}<<<<<\n")
    except KeyboardInterrupt:
        print("KeyboardInterrupt detected. Cleaning up...")


if __name__ == '__main__':
    main()
