```bash
nikto -ask=no -Tuning=x4567890ac -nointeractive -host http://localhost:9090 2>&1 | tee "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp9090/tcp_9090_http_nikto.txt"
```

[/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp9090/tcp_9090_http_nikto.txt](file:///Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp9090/tcp_9090_http_nikto.txt):

```
- ***** TLS/SSL support not available (see docs for SSL install) *****
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          127.0.0.1
+ Target Hostname:    localhost
+ Target Port:        9090
+ Start Time:         2025-06-15 16:21:50 (GMT8)
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /: Retrieved access-control-allow-origin header: *.
+ OPTIONS: Allowed HTTP Methods: GET .
+ 7476 requests: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2025-06-15 16:21:56 (GMT8) (6 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```
