```bash
feroxbuster -u http://localhost:8000/ -t 10 -w /Users/lizi/Library/Application Support/AutoRecon/wordlists/dirbuster.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -q -e -r -o "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp8000/tcp_8000_http_feroxbuster_dirbuster.txt"
```