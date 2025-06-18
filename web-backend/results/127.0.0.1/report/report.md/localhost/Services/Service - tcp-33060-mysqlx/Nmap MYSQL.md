```bash
nmap -vv --reason -Pn -T4 -sV -p 33060 --script="banner,(mysql* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp33060/tcp_33060_mysql_nmap.txt" -oX "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp33060/xml/tcp_33060_mysql_nmap.xml" localhost
```

[/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp33060/tcp_33060_mysql_nmap.txt](file:///Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp33060/tcp_33060_mysql_nmap.txt):

```
# Nmap 7.95 scan initiated Sun Jun 15 16:22:02 2025 as: nmap -vv --reason -Pn -T4 -sV -p 33060 "--script=banner,(mysql* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN /Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp33060/tcp_33060_mysql_nmap.txt -oX /Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp33060/xml/tcp_33060_mysql_nmap.xml localhost
Warning: Hostname localhost resolves to 2 IPs. Using 127.0.0.1.
Nmap scan report for localhost (127.0.0.1)
Host is up, received user-set (0.00012s latency).
Other addresses for localhost (not scanned): ::1
Scanned at 2025-06-15 16:22:02 CST for 0s

PORT      STATE SERVICE REASON  VERSION
33060/tcp open  mysqlx  syn-ack MySQL X protocol listener
|_banner: \x05\x00\x00\x00\x0B\x08\x05\x1A\x00

Read data files from: /usr/local/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jun 15 16:22:02 2025 -- 1 IP address (1 host up) scanned in 0.25 seconds

```
