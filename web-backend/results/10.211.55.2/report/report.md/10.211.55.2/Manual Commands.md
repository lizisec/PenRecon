```bash
[*] microsoft-ds on tcp/445

	[-] Bruteforce SMB

		crackmapexec smb 10.211.55.2 --port=445 -u "/usr/share/seclists/Usernames/top-usernames-shortlist.txt" -p "/usr/share/seclists/Passwords/darkweb2017-top100.txt"

	[-] Lookup SIDs

		impacket-lookupsid '[username]:[password]@10.211.55.2'

	[-] Nmap scans for SMB vulnerabilities that could potentially cause a DoS if scanned (according to Nmap). Be careful:

		nmap -vv --reason -Pn -T4 -sV -p 445 --script="smb-vuln-* and dos" --script-args="unsafe=1" -oN "/home/lizi/Desktop/myproj/PenRecon/web-backend/results/10.211.55.2/scans/tcp445/tcp_445_smb_vulnerabilities.txt" -oX "/home/lizi/Desktop/myproj/PenRecon/web-backend/results/10.211.55.2/scans/tcp445/xml/tcp_445_smb_vulnerabilities.xml" 10.211.55.2


```