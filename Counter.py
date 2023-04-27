import pyshark



# Counter Helper Methods
def Ct_sack(packet):
    ct = 0
    if hasattr(packet.tcp.options, "sack"):
        ct = packet.tcp.options.sack.count
    return ct

def Ct_c0(packet):
    ct = 0
    if hasattr(packet.tcp, 'payload'):
        if len(packet.tcp.payload) > 0:
            ct = 1
    return ct


def Ct_cd(packet):
    ct = 0
    return ct


def Ct_cf(packet):
    ct = 0
    return ct


def Ct_s0(packet):
    ct = 0
    return ct


def Ct_sd(packet):
    ct = 0
    return ct


def Ct_sf(packet):
    ct = 0
    return ct


def Ct_ca1(packet):
    ct = 0
    return ct


def Ct_ca2(packet):
    ct = 0
    return ct


def Ct_ca3(packet):
    ct = 0
    return ct


def Ct_ca4(packet):
    ct = 0
    return ct


def Ct_sa1(packet):
    ct = 0
    return ct


def Ct_sa2(packet):
    ct = 0
    return ct


def Ct_sa3(packet):
    ct = 0
    return ct


def Ct_sa4(packet):
    ct = 0
    return ct