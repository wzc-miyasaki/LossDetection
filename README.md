# README

#### Library

- Pyshark



#### Pyshark 

*pyshark* is python wrapper for tshark, allowing python packet parsing using wireshark dissectors. The path to the Tshark.exe is required when using this library.

`tshark.exe` should be under the `Wireshark` application folder  (for Windows).  Use that path as parameter to run pyshark library.

```python
pyshark.FileCapture(path, tshark_path=tShark_exe_Path)
```

In my case, the tshark.exe is located at `"C:\Applications\Wireshark\tshark.exe"`

&nbsp;

&nbsp;

#### How to start the feature extraction

###### 1. Create a `BucketTable` instance

```python
tcp = "./tcp.csv"
udp = "./udp.csv"
path = 'target_files.txt'

t = BucketTable(row=5, bktSize=10)
t.SetTargetIP("192.168.1.11")
t.SetCSVPath(tcp, udp)

target = GetListOfpcapPaths(path)
for pcap in target:
    t.ReadPCAP(pcap)
    print(f">>>>> DONE With {pcap}<<<<<")
```

A bucket table is a `n` ✖️`m` 2D array. Each row of the table will hold `buckets`. Each bucket maintains the counters for TCP packets and UDP packets. 



1. Couple of parameters are required to be setup : 
    - `tcp` :  the csv file path using for holding the the output of TCP packet feature extractions
    - `udp` :   the csv file path using for holding the the output of UDPpacket feature extractions
    - `path` :  It's a txt file containing a list of the PCAP file paths. Our code will visit each pcap file recoreded in the txt file, and generate the output to the tcp.csv & udp.csv

&nbsp;

2. It's necessary to set the "**target IP**" address before reading pcap file. The reason is that the table will examine the ip address to determine whether it is a packet from the client or the server.

    - If the the source ip matches with the target IP, it is a **client packet**

    - If the the destination ip matches with the target IP, it is a **server packet**

&nbsp;

3. The `ReadPCAP` will get started to insert all the packet into the bucket table. 



