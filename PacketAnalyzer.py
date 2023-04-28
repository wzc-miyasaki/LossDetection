import pyshark


TSharkPATH = "C:\Applications\Wireshark\\tshark.exe"
TIME_OUT = 10   #ms
INTERFACE = "Wi-Fi"

class PacketAnalyzer:
    def __init__(self, tSarkPath):
        self.tSharkPath = tSarkPath
        self.filter = ""

    def SetTSharkPath(self, path):
        self.tSharkPath = path

    def SetFilter(self, filter):
        self.filter = filter


    def OpenPCAP(self, path):
        """
        :param path: pcap path
        :return: a FileCapture Object, which is like a list of packets read from the pcap file
        """
        return pyshark.FileCapture(path, tshark_path=self.tSharkPath, display_filter=self.filter)

def test():
    # Specify the path to your PCAP file
    pcap_file = 'Wireshark_802_11.pcap'
    pcap_sample = 'sample.pcap'

    # 1. Open the PCAP file using pyshark
    test = PacketAnalyzer(TSharkPATH)
    test.SetFilter("")
    capture = test.OpenPCAP(pcap_file)
    ct = 0
    cp = 0
    for p in capture:
        if "IP" not in p:
            ct += 1
        if "IP" in p:
            cp += 1
    print(ct)
    print(cp)






    # 2. Live Capture
    # capture = pyshark.LiveCapture(interface=INTERFACE, tshark_path=TSharkPATH)
    # capture.sniff(TIME_OUT)
    # for packet in capture.sniff_continuously(packet_count=5):
    #     print('Just arrived:', packet)


    # Close the capture file
    capture.close()

if __name__ == '__main__':
    test()