# LossDetection



#### Pyshark 

*pyshark* is python wrapper for tshark, allowing python packet parsing using wireshark dissectors. The path to the Tshark.exe is required when using this library.

`tshark.exe` should be under the `Wireshark` application folder  (for Windows).  Use that path as parameter to run pyshark library.

```python
pyshark.FileCapture(path, tshark_path=tShark_exe_Path)
```

In my case, the tshark.exe is located at `"C:\Applications\Wireshark\tshark.exe"`



#### How to start the feature extraction

###### 1. Create a `BucketTable` instance

```python
pcap_file = 'Wireshark_802_11.pcap'
t = BucketTable(row=5, bktSize=10)
t.SetServerAndClientIP(ips="23.43.124.211", ipc="10.26.85.14")
t.ReadPCAP(file2)
```

- A pcap file must be provided for BucketTable.  

1. A bucket table is a `n` ✖️`m` 2D array. Each row of the table will hold `buckets`. Each bucket maintains the counters for TCP packets and UDP packets. 

2. It's necessary to set the "server IP" and "client IP" before reading pcap file. The reason is that the table will examine the ip address to determine whether it is a packet from the client or the server.

3. The `ReadPCAP` will get started to insert all the packet into the bucket table. 



