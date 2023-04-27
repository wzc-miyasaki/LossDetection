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
    test.SetFilter("tcp && tcp.options.sack.count == 1")
    capture = test.OpenPCAP(pcap_sample)
    ct = 0
    for p in capture:
        if hasattr(p.tcp, "options_sack_count"):
            ct += int(p.tcp.options_sack_count)
    print(ct)






    # 2. Live Capture
    # capture = pyshark.LiveCapture(interface=INTERFACE, tshark_path=TSharkPATH)
    # capture.sniff(TIME_OUT)
    # for packet in capture.sniff_continuously(packet_count=5):
    #     print('Just arrived:', packet)


    # Close the capture file
    capture.close()

if __name__ == '__main__':
    test()