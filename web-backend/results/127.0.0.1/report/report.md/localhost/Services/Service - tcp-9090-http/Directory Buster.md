```bash
feroxbuster -u http://localhost:9090/ -t 10 -w /Users/lizi/Library/Application Support/AutoRecon/wordlists/dirbuster.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -q -e -r -o "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp9090/tcp_9090_http_feroxbuster_dirbuster.txt"
```