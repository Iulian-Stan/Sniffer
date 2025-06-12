# Network Sniffer

## Features

This application:
1. monitors network traffic and parses IP(Internet Protocol) packets
2. parses IP header fields
3. analyses underlying protocol and parses header fields for TCP(Transmission Control Protocol), UDP(User Datagram Protocol) & ICMP(Internet Control Message Protocol)
4. in can also extract DNS(Domain Name System) packets
from TCP and performs same operation fo header parsing
```
    +-----+     +-----+     +-----+
    | DNS |     | ... | ... | ... |
    +-----+     +-----+     +-----+
       |           |           |
    +-----+     +-----+     +-----+
    | TCP |     | UDP | ... | ... |
    +-----+     +-----+     +-----+
       |           |           |
    +-------------------------------+
    |    Internet Protocol & ICMP   |
    +-------------------------------+
                   |
      +---------------------------+
      |   Local Network Protocol  |
      +---------------------------+
```
All the parsed information is displayed in the Windows Forms based user interface.

**Note:** this application requires elevated privileges to access network interfaces.

## References

* [IP - RFC791](https://www.rfc-editor.org/rfc/rfc791.html)
* [TCP - RFP793](https://www.rfc-editor.org/rfc/rfc793.html)
* [UDP - RFC768](https://www.rfc-editor.org/rfc/rfc768.html)
* [ICMP - RFC792](https://www.rfc-editor.org/rfc/rfc792.html)
* [DNS - RFC1035](https://www.rfc-editor.org/rfc/rfc1035.html)
