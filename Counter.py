import pyshark


# Counter Helper Methods

##  TCP
def Ct_sack(packet):
    """
    count the SACK number
    """
    if hasattr(packet.tcp, "options_sack_count"):
        return int(packet.tcp.options_sack_count)
    return 0

def Ct_c0(packet):
    """
    return 1 if length of tcp payload == 0
    """
    res = False
    if hasattr(packet.tcp, 'len'):
        res = (int(packet.tcp.len) == 0)
    return int(res)


def Ct_cd(packet):
    """
    return 1 if length of tcp payload > 0
    """
    res = False
    if hasattr(packet.tcp, 'len'):
        res = (int(packet.tcp.len) > 0)
    return int(res)


def Ct_cf(packet):
    """
    If TCP packet has both SYN == 1 and PUSH == 1
    """
    res = packet.tcp.flags_push == "1" and packet.tcp.flags_syn == "1"
    return int(res)


def Ct_s0(packet):
    return Ct_c0(packet)


def Ct_sd(packet):
    return Ct_cd(packet)


def Ct_sf(packet):
    return Ct_cf(packet)


def Ct_ca1(packet):
    """
        payload interval [0, 83]
        """
    res = False
    if hasattr(packet.tcp, "payload"):
        res = (len(packet.tcp.payload) > 0)
    return int(res)


def Ct_ca2(packet):
    """
        payload interval [83, 375]
        """
    res = False
    if hasattr(packet.tcp, "payload"):
        res = (len(packet.tcp.payload) > 82)
    return int(res)


def Ct_ca3(packet):
    """
            payload interval [375, 1100]
            """
    res = False
    if hasattr(packet.tcp, "payload"):
        res = (len(packet.tcp.payload) > 374)
    return int(res)


def Ct_sa1(packet):
    return Ct_ca1(packet)


def Ct_sa2(packet):
    return Ct_ca2(packet)


def Ct_sa3(packet):
    return Ct_ca3(packet)


##  UDP
def Cu_payloadSz(packet, boundary):
    res = False
    if hasattr(packet.udp, "payload"):
        res = len(packet.udp.payload) > boundary
    return int(res)