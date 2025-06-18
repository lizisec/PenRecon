```bash
ffuf -u http://localhost:8000/ -t 10 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.localhost" -mc all -fs 22 -r -noninteractive -s | tee "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp8000/tcp_8000_http_localhost_vhosts_subdomains-top1million-110000.txt"
```

[/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp8000/tcp_8000_http_localhost_vhosts_subdomains-top1million-110000.txt](file:///Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp8000/tcp_8000_http_localhost_vhosts_subdomains-top1million-110000.txt):

```

```
