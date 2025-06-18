```bash
nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -oN "/home/lizi/Desktop/myproj/PenRecon/web-backend/results/10.211.55.2/scans/_quick_tcp_nmap.txt" -oX "/home/lizi/Desktop/myproj/PenRecon/web-backend/results/10.211.55.2/scans/xml/_quick_tcp_nmap.xml" 10.211.55.2

nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN "/home/lizi/Desktop/myproj/PenRecon/web-backend/results/10.211.55.2/scans/_full_tcp_nmap.txt" -oX "/home/lizi/Desktop/myproj/PenRecon/web-backend/results/10.211.55.2/scans/xml/_full_tcp_nmap.xml" 10.211.55.2

enum4linux-ng -A -d -v 10.211.55.2 2>&1

nbtscan -rvh 10.211.55.2 2>&1

nmap -vv --reason -Pn -T4 -sV -p 445 --script="banner,(nbstat or smb* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "/home/lizi/Desktop/myproj/PenRecon/web-backend/results/10.211.55.2/scans/tcp445/tcp_445_smb_nmap.txt" -oX "/home/lizi/Desktop/myproj/PenRecon/web-backend/results/10.211.55.2/scans/tcp445/xml/tcp_445_smb_nmap.xml" 10.211.55.2

smbclient -L //10.211.55.2 -N -I 10.211.55.2 2>&1

smbmap -H 10.211.55.2 -P 445 2>&1

smbmap -u null -p "" -H 10.211.55.2 -P 445 2>&1

smbmap -H 10.211.55.2 -P 445 -r 2>&1

smbmap -u null -p "" -H 10.211.55.2 -P 445 -r 2>&1

smbmap -H 10.211.55.2 -P 445 -x "ipconfig /all" 2>&1

smbmap -u null -p "" -H 10.211.55.2 -P 445 -x "ipconfig /all" 2>&1


```