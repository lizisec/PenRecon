```bash
nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN "/home/lizi/Desktop/myproj/PenRecon/web-backend/results/10.211.55.2/scans/_full_tcp_nmap.txt" -oX "/home/lizi/Desktop/myproj/PenRecon/web-backend/results/10.211.55.2/scans/xml/_full_tcp_nmap.xml" 10.211.55.2
```

[/home/lizi/Desktop/myproj/PenRecon/web-backend/results/10.211.55.2/scans/_full_tcp_nmap.txt](file:///home/lizi/Desktop/myproj/PenRecon/web-backend/results/10.211.55.2/scans/_full_tcp_nmap.txt):

```
# Nmap 7.95 scan initiated Wed Jun 18 15:43:41 2025 as: /usr/lib/nmap/nmap --privileged -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /home/lizi/Desktop/myproj/PenRecon/web-backend/results/10.211.55.2/scans/_full_tcp_nmap.txt -oX /home/lizi/Desktop/myproj/PenRecon/web-backend/results/10.211.55.2/scans/xml/_full_tcp_nmap.xml 10.211.55.2
Nmap scan report for 10.211.55.2
Host is up, received arp-response (0.00091s latency).
Scanned at 2025-06-18 15:43:42 CST for 652s
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE       REASON         VERSION
445/tcp   open  microsoft-ds? syn-ack ttl 64
7890/tcp  open  socks5        syn-ack ttl 64 (No authentication; connection failed)
| socks-auth-info: 
|   No authentication
|   No authentication
|_  No authentication
| socks-open-proxy: 
|   status: open
|   versions: 
|     socks4
|_    socks5
58172/tcp open  unknown       syn-ack ttl 64
MAC Address: 8A:66:5A:01:D0:64 (Unknown)
Device type: general purpose
Running: Apple macOS 11.X|12.X|13.X
OS CPE: cpe:/o:apple:mac_os_x:11 cpe:/o:apple:mac_os_x:12 cpe:/o:apple:mac_os_x:13
OS details: Apple macOS 11 (Big Sur) - 13 (Ventura) or iOS 16 (Darwin 20.6.0 - 22.4.0)
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=6/18%OT=445%CT=1%CU=34197%PV=Y%DS=1%DC=D%G=Y%M=8A665A%
OS:TM=685270BA%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=2%ISR=10A%TI=Z%CI=RD%II
OS:=RI%TS=22)OPS(O1=M5B4NW6NNT11SLL%O2=M5B4NW6NNT11SLL%O3=M5B4NW6NNT11%O4=M
OS:5B4NW6NNT11SLL%O5=M5B4NW6NNT11SLL%O6=M5B4NNT11SLL)WIN(W1=FFFF%W2=FFFF%W3
OS:=FFFF%W4=FFFF%W5=FFFF%W6=FFFF)ECN(R=Y%DF=Y%T=40%W=FFFF%O=M5B4NW6SLL%CC=Y
OS:%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=4
OS:0%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=N%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%
OS:Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=N%T=40%W=0%S=Z%
OS:A=S%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=38%UN=0%RIPL=G%RID=G%RIPCK=G%RU
OS:CK=0%RUD=G)IE(R=Y%DFI=S%T=40%CD=S)

Uptime guess: 0.000 days (since Wed Jun 18 15:54:28 2025)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros

Host script results:
| nbstat: NetBIOS name: LIZI, NetBIOS user: <unknown>, NetBIOS MAC: 8a:66:5a:01:d0:64 (unknown)
| Names:
|   LIZI<00>             Flags: <unique><active>
|   LIZI<20>             Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
| Statistics:
|   8a:66:5a:01:d0:64:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
| smb2-time: 
|   date: 2025-06-18T07:51:26
|_  start_date: N/A
|_clock-skew: -3m06s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 25064/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 23716/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 25615/udp): CLEAN (Failed to receive data)
|   Check 4 (port 26953/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:0:2: 
|_    Message signing enabled and required

TRACEROUTE
HOP RTT     ADDRESS
1   0.91 ms 10.211.55.2

Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Jun 18 15:54:34 2025 -- 1 IP address (1 host up) scanned in 653.11 seconds

```
