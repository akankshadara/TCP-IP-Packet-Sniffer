# TCP-IP-Packet-Sniffer (Raw Socket Implementation in C)


A packet sniffer allows the user to view and capture all the information that is transmitted over the network, as packets of data. 

The aim of this application is to read packets that travel across various layers of the Transmission Control Protocol/Internet Protocol (TCP/IP) model of network architecture. The packet sniffer will analyze the network traffic so as to allow users to get a practical understanding of the flow of packets in a network. 

It will be used to capture and analyze the following protocols’ header information from the packets:

Application Layer: HTTP, DNS
Transport Layer: TCP, UDP
Network Layer: IPv4, IPv6
Data Link Layer: ARP

The packets captured will be analyzed to extract and display the header information along with other relevant parameters for the selected protocols. 

**Usage:** 

Execute the following command on the command line:
```{r, engine='bash', count_lines}
To compile: gcc sniffer.c

To run: sudo ./a.out

To stop: ctrl+c
```

Count of packets containing different protocols is displayed on the terminal. Header information of the packets in printed in a file named 'log.txt'
