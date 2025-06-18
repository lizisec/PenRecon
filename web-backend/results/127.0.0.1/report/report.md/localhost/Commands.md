```bash
nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -oN "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/_quick_tcp_nmap.txt" -oX "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/xml/_quick_tcp_nmap.xml" localhost

nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/_full_tcp_nmap.txt" -oX "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/xml/_full_tcp_nmap.xml" localhost

nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -oN "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/_quick_tcp_nmap.txt" -oX "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/xml/_quick_tcp_nmap.xml" localhost

nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/_full_tcp_nmap.txt" -oX "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/xml/_full_tcp_nmap.xml" localhost

nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -oN "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/_quick_tcp_nmap.txt" -oX "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/xml/_quick_tcp_nmap.xml" localhost

nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/_full_tcp_nmap.txt" -oX "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/xml/_full_tcp_nmap.xml" localhost

nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -oN "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/_quick_tcp_nmap.txt" -oX "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/xml/_quick_tcp_nmap.xml" localhost

nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/_full_tcp_nmap.txt" -oX "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/xml/_full_tcp_nmap.xml" localhost

enum4linux -a -M -l -d localhost 2>&1

nbtscan -rvh 127.0.0.1 2>&1

nmap -vv --reason -Pn -T4 -sV -p 445 --script="banner,(nbstat or smb* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp445/tcp_445_smb_nmap.txt" -oX "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp445/xml/tcp_445_smb_nmap.xml" localhost

smbclient -L //localhost -N -I localhost 2>&1

smbmap -H localhost -P 445 2>&1

nmap -vv --reason -Pn -T4 -sV -p 3306 --script="banner,(mysql* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp3306/tcp_3306_mysql_nmap.txt" -oX "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp3306/xml/tcp_3306_mysql_nmap.xml" localhost

sslscan --show-certificate --no-colour localhost:4001 2>&1

feroxbuster -u http://localhost:8000/ -t 10 -w /Users/lizi/Library/Application Support/AutoRecon/wordlists/dirbuster.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -q -e -r -o "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp8000/tcp_8000_http_feroxbuster_dirbuster.txt"

curl -sSikf http://localhost:8000/.well-known/security.txt

curl -sSikf http://localhost:8000/robots.txt

curl -sSik http://localhost:8000/

nikto -ask=no -Tuning=x4567890ac -nointeractive -host http://localhost:8000 2>&1 | tee "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp8000/tcp_8000_http_nikto.txt"

nmap -vv --reason -Pn -T4 -sV -p 8000 --script="banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)" -oN "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp8000/tcp_8000_http_nmap.txt" -oX "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp8000/xml/tcp_8000_http_nmap.xml" localhost

ffuf -u http://localhost:8000/ -t 10 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.localhost" -mc all -fs 22 -r -noninteractive -s | tee "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp8000/tcp_8000_http_localhost_vhosts_subdomains-top1million-110000.txt"

whatweb --color=never --no-errors -a 3 -v http://localhost:8000 2>&1

feroxbuster -u http://localhost:9090/ -t 10 -w /Users/lizi/Library/Application Support/AutoRecon/wordlists/dirbuster.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -q -e -r -o "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp9090/tcp_9090_http_feroxbuster_dirbuster.txt"

curl -sSikf http://localhost:9090/.well-known/security.txt

curl -sSikf http://localhost:9090/robots.txt

curl -sSik http://localhost:9090/

nikto -ask=no -Tuning=x4567890ac -nointeractive -host http://localhost:9090 2>&1 | tee "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp9090/tcp_9090_http_nikto.txt"

nmap -vv --reason -Pn -T4 -sV -p 9090 --script="banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)" -oN "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp9090/tcp_9090_http_nmap.txt" -oX "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp9090/xml/tcp_9090_http_nmap.xml" localhost

ffuf -u http://localhost:9090/ -t 10 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.localhost" -mc all -fs 27 -r -noninteractive -s | tee "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp9090/tcp_9090_http_localhost_vhosts_subdomains-top1million-110000.txt"

whatweb --color=never --no-errors -a 3 -v http://localhost:9090 2>&1

smbmap -u null -p "" -H localhost -P 445 2>&1

smbmap -H localhost -P 445 -r 2>&1

smbmap -u null -p "" -H localhost -P 445 -r 2>&1

smbmap -H localhost -P 445 -x "ipconfig /all" 2>&1

smbmap -u null -p "" -H localhost -P 445 -x "ipconfig /all" 2>&1

sslscan --show-certificate --no-colour localhost:4301 2>&1

nmap -vv --reason -Pn -T4 -sV -p 33060 --script="banner,(mysql* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp33060/tcp_33060_mysql_nmap.txt" -oX "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp33060/xml/tcp_33060_mysql_nmap.xml" localhost


```