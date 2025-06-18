```
[*] Port scan Top TCP Ports (top-tcp-ports) ran a command which returned a non-zero exit code (-9).
[-] Command: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -oN "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/_quick_tcp_nmap.txt" -oX "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/xml/_quick_tcp_nmap.xml" localhost
[-] Error Output:
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Warning: Hostname localhost resolves to 2 IPs. Using 127.0.0.1.


[*] Service scan nbtscan (tcp/445/microsoft-ds/nbtscan) ran a command which returned a non-zero exit code (127).
[-] Command: nbtscan -rvh 127.0.0.1 2>&1
[-] Error Output:


[*] Service scan Directory Buster (tcp/8000/http/dirbuster) ran a command which returned a non-zero exit code (2).
[-] Command: feroxbuster -u http://localhost:8000/ -t 10 -w /Users/lizi/Library/Application Support/AutoRecon/wordlists/dirbuster.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -q -e -r -o "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp8000/tcp_8000_http_feroxbuster_dirbuster.txt"
[-] Error Output:
error: unexpected argument 'Support/AutoRecon/wordlists/dirbuster.txt' found

Usage: feroxbuster [OPTIONS]

For more information, try '--help'.


[*] Service scan whatweb (tcp/8000/http/whatweb) ran a command which returned a non-zero exit code (127).
[-] Command: whatweb --color=never --no-errors -a 3 -v http://localhost:8000 2>&1
[-] Error Output:


[*] Service scan Directory Buster (tcp/9090/http/dirbuster) ran a command which returned a non-zero exit code (2).
[-] Command: feroxbuster -u http://localhost:9090/ -t 10 -w /Users/lizi/Library/Application Support/AutoRecon/wordlists/dirbuster.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -q -e -r -o "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp9090/tcp_9090_http_feroxbuster_dirbuster.txt"
[-] Error Output:
error: unexpected argument 'Support/AutoRecon/wordlists/dirbuster.txt' found

Usage: feroxbuster [OPTIONS]

For more information, try '--help'.


[*] Service scan whatweb (tcp/9090/http/whatweb) ran a command which returned a non-zero exit code (127).
[-] Command: whatweb --color=never --no-errors -a 3 -v http://localhost:9090 2>&1
[-] Error Output:


[*] Service scan SMBClient (tcp/445/microsoft-ds/smbclient) ran a command which returned a non-zero exit code (1).
[-] Command: smbclient -L //localhost -N -I localhost 2>&1
[-] Error Output:


[*] Service scan SMBMap (tcp/445/microsoft-ds/smbmap) ran a command which returned a non-zero exit code (127).
[-] Command: smbmap -H localhost -P 445 2>&1
[-] Error Output:


[*] Service scan SMBMap (tcp/445/microsoft-ds/smbmap) ran a command which returned a non-zero exit code (127).
[-] Command: smbmap -u null -p "" -H localhost -P 445 2>&1
[-] Error Output:


[*] Service scan SMBMap (tcp/445/microsoft-ds/smbmap) ran a command which returned a non-zero exit code (127).
[-] Command: smbmap -H localhost -P 445 -r 2>&1
[-] Error Output:


[*] Service scan SMBMap (tcp/445/microsoft-ds/smbmap) ran a command which returned a non-zero exit code (127).
[-] Command: smbmap -u null -p "" -H localhost -P 445 -r 2>&1
[-] Error Output:


[*] Service scan SMBMap (tcp/445/microsoft-ds/smbmap) ran a command which returned a non-zero exit code (127).
[-] Command: smbmap -H localhost -P 445 -x "ipconfig /all" 2>&1
[-] Error Output:


[*] Service scan SMBMap (tcp/445/microsoft-ds/smbmap) ran a command which returned a non-zero exit code (127).
[-] Command: smbmap -u null -p "" -H localhost -P 445 -x "ipconfig /all" 2>&1
[-] Error Output:


[*] Service scan Enum4Linux (tcp/445/microsoft-ds/enum4linux) ran a command which returned a non-zero exit code (1).
[-] Command: enum4linux -a -M -l -d localhost 2>&1
[-] Error Output:



```