rep-5:
```
team29@ns03:~$ host sdu.dk
sdu.dk has address 52.233.201.66
sdu.dk mail is handled by 0 sdu-dk.i-v1.mx.microsoft.
```

alternative für rep-5:
```
team29@ns03:~$ nslookup
> set type=mx
> sdu.dk
Server:         192.168.83.1
Address:        192.168.83.1#53

Non-authoritative answer:
sdu.dk  mail exchanger = 0 sdu-dk.i-v1.mx.microsoft.
```

rep-6, not working?
```
team29@ns03:~/Desktop$ host sdu-dk.i-v1.mx.microsoft
sdu-dk.i-v1.mx.microsoft has address 52.101.68.27
sdu-dk.i-v1.mx.microsoft has address 52.101.73.26
sdu-dk.i-v1.mx.microsoft has address 52.101.73.4
sdu-dk.i-v1.mx.microsoft has address 52.101.73.2
sdu-dk.i-v1.mx.microsoft has IPv6 address 2a01:111:f403:ca09::8
sdu-dk.i-v1.mx.microsoft has IPv6 address 2a01:111:f403:ca04::10
sdu-dk.i-v1.mx.microsoft has IPv6 address 2a01:111:f403:ca09::4
sdu-dk.i-v1.mx.microsoft has IPv6 address 2a01:111:f403:ca09::5
```

rep-7:
```
❯ smap -sV sdu.dk
Starting Nmap 9.99 ( https://nmap.org ) at 2025-05-13 20:20 CEST
Nmap scan report for sdu.dk (52.233.201.66)
Host is up.
rDNS record for 52.233.201.66: sdu.dk

PORT    STATE SERVICE  VERSION
443/tcp open  ftp      IIS ftpd 10.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Nmap done: 1 IP address (1 host up) scanned in 0.66 seconds```

rep-8:
```
filter:
tcp.flags.syn == 1 and tcp.flags.ack == 0

suchen nach 10.0.0.x in destination

wenn attacker ip gefunden dann:

ip.src = 100.2.1.5 and tcp.dstport == 445
und
ip.dst == 100.2.1.5 and tcp.srcport == 445

dann responses anschauen und entscheiden

| Letter | Response Type | Response                       |
| ------ | ------------- | ------------------------------------------- |
| A      | SYN/ACK       | ? |
| B      | RST           | Irgendwas mit RST                      |
| C      | No reply      | No response packet                          |
| D      | ICMP error    | Destination Unreachable schon bei Request            |

```

rep-9:
```
Statistics -> Endpoints
look for IP that is sending a lot more traffic than others

then filter for ip:
ip.src == 192.168.0.117
ip.src == 192.168.104.2

we see a lot of requests on the same destination with changing ports (protocol mostly tcp; sometimes http)

however it is always trying to enter port 80 which could indicate a DoS or a brute-force

when looking at the provided page its a login page and when filtering for:
ip.dst == 192.168.0.117 
we can see that the user tries different username and password combinations which indicates a brute-force attack; now we only need to find the username/password combination that worked

using the filter:
http.request.method == "POST"
we can see all the post requests made to the target

FINAL WORKING TRY:
use filter:
frame contains "success" 
(filters content by string)
we found the successfull response (with username Sally_Santos and password Card)
```

rep-11
```
tcpdump -r mawi_team29.pcap -tt -n -c 10
-r: pcap file
-tt: Print the timestamp, as seconds since January 1, 1970, 00:00:00, UTC
-n: Don't convert addresses (i.e., host addresses, port numbers, etc.) to names (sonst wird z.B. port 80 direkt auf http übersetzt
-c 10: Exit after receiving or reading 10 packets
```

rep-12:
```
[1778139 rows x 8 columns]
6: 735499
1: 694092
47: 242159
17: 104982
58: 1213
50: 176
103: 16
41: 2
```
