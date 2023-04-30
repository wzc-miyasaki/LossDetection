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

def Ct_ca(packet, interval_st, interval_ed):
    """
    If the payload size is less than interval_ed but greater than interval_st, then return 1,
    otherwise return 0.
    """
    res = False
    if hasattr(packet.tcp, "payload"):
        res = (len(packet.tcp.payload) > interval_st) and (len(packet.tcp.payload) < interval_ed)
    return int(res)


##  UDP
def Cu_payloadSz(packet, boundary):
    ret = len(packet.udp.payload)
    if ret > 0 and ret <= boundary:
        return 1
    elif ret > boundary and ret <= 140:
        return 2
    elif ret > 140 and ret <= 1100:
        return 3
    elif ret > 1100 and ret <= 1500:
        return 4
    return 0


# Update
def UpdateMin(a, b):
    if a == -1:
        return b
    elif b == -1:
        return a
    else:
        return min(a, b)