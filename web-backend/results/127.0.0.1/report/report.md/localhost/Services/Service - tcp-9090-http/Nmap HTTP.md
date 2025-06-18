```bash
nmap -vv --reason -Pn -T4 -sV -p 9090 --script="banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)" -oN "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp9090/tcp_9090_http_nmap.txt" -oX "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp9090/xml/tcp_9090_http_nmap.xml" localhost
```

[/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp9090/tcp_9090_http_nmap.txt](file:///Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp9090/tcp_9090_http_nmap.txt):

```
# Nmap 7.95 scan initiated Sun Jun 15 16:21:49 2025 as: nmap -vv --reason -Pn -T4 -sV -p 9090 "--script=banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)" -oN /Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp9090/tcp_9090_http_nmap.txt -oX /Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp9090/xml/tcp_9090_http_nmap.xml localhost
Warning: Hostname localhost resolves to 2 IPs. Using 127.0.0.1.
Nmap scan report for localhost (127.0.0.1)
Host is up, received user-set (0.00011s latency).
Other addresses for localhost (not scanned): ::1
Scanned at 2025-06-15 16:21:49 CST for 74s

Bug in http-security-headers: no string output.
PORT     STATE SERVICE REASON  VERSION
9090/tcp open  http    syn-ack Golang net/http server
|_http-fetch: Please enter the complete path of the directory to save data in.
|_http-malware-host: Host appears to be clean
| http-methods: 
|_  Supported Methods: GET
|_http-title: Site doesn't have a title (application/json).
| http-vhosts: 
|_128 names had status 405
|_http-chrono: Request times for /; avg: 162.21ms; min: 158.74ms; max: 164.90ms
|_http-wordpress-users: [Error] Wordpress installation was not found. We couldn't find wp-login.php
|_http-jsonp-detection: Couldn't find any JSONP endpoints.
|_http-devframework: Couldn't determine the underlying framework or CMS. Try increasing 'httpspider.maxpagecount' value to spider more pages.
| http-headers: 
|   Content-Type: application/json
|   Vary: Origin
|   Date: Sun, 15 Jun 2025 08:22:46 GMT
|   Content-Length: 27
|   Connection: close
|   
|_  (Request type: GET)
| http-useragent-tester: 
|   Status for browser useragent: 401
|   Allowed User Agents: 
|     Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
|     libwww
|     lwp-trivial
|     libcurl-agent/1.0
|     PHP/
|     Python-urllib/2.5
|     GT::WWW
|     Snoopy
|     MFC_Tear_Sample
|     HTTP::Lite
|     PHPCrawl
|     URI::Fetch
|     Zend_Http_Client
|     http client
|     PECL::HTTP
|     Wget/1.13.4 (linux-gnu)
|_    WWW-Mechanize/1.34
|_http-litespeed-sourcecode-download: Request with null byte did not work. This web server might not be vulnerable
|_http-cors: GET POST PUT DELETE OPTIONS PATCH
| http-sitemap-generator: 
|   Directory structure:
|   Longest directory structure:
|     Depth: 0
|     Dir: /
|   Total files found (by extension):
|_    
|_http-wordpress-enum: Nothing found amongst the top 100 resources,use --script-args search-limit=<number|all> for deeper analysis)
| http-enum: 
|   /cache/backup/: Possible backup (401 Unauthorized)
|   /cache/: Potentially interesting folder (401 Unauthorized)
|   /configs/: Potentially interesting folder (401 Unauthorized)
|_  /script/: Potentially interesting folder (401 Unauthorized)
| http-errors: 
| Spidering limited to: maxpagecount=40; withinhost=localhost
|   Found the following error pages: 
|   
|   Error Code: 401
|_  	http://localhost:9090/
|_http-mobileversion-checker: No mobile version detected.
|_http-drupal-enum: Nothing found amongst the top 100 resources,use --script-args number=<number|all> for deeper analysis)
|_http-referer-checker: Couldn't find any cross-domain scripts.
| http-auth-finder: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=localhost
|   url                     method
|_  http://localhost:9090/  HTTP: Server returned no authentication headers.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-comments-displayer: Couldn't find any comments.
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-date: Sun, 15 Jun 2025 08:22:31 GMT; 0s from local time.
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 Not Found
|     Content-Type: text/plain; charset=utf-8
|     Vary: Origin
|     X-Content-Type-Options: nosniff
|     Date: Sun, 15 Jun 2025 08:22:26 GMT
|     Content-Length: 19
|     page not found
|   GenericLines, Help, LPDString, RTSPRequest, SIPOptions, SSLSessionReq, Socks5, SqueezeCenter_CLI: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 401 Unauthorized
|     Content-Type: application/json
|     Vary: Origin
|     Date: Sun, 15 Jun 2025 08:21:56 GMT
|     Content-Length: 27
|     {"message":"Unauthorized"}
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Allow: GET
|     Vary: Origin
|     Date: Sun, 15 Jun 2025 08:22:11 GMT
|     Content-Length: 0
|   OfficeScan: 
|     HTTP/1.1 400 Bad Request: missing required Host header
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|_    Request: missing required Host header
| http-method-tamper: 
|   VULNERABLE:
|   Authentication bypass by HTTP verb tampering
|     State: VULNERABLE (Exploitable)
|       This web server contains password protected resources vulnerable to authentication bypass
|       vulnerabilities via HTTP verb tampering. This is often found in web servers that only limit access to the
|        common HTTP methods and in misconfigured .htaccess files.
|              
|     Extra information:
|       
|   URIs suspected to be vulnerable to HTTP verb tampering:
|     / [HEAD]
|   
|     References:
|       https://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29
|       http://www.imperva.com/resources/glossary/http_verb_tampering.html
|       http://www.mkit.com.ar/labs/htexploit/
|_      http://capec.mitre.org/data/definitions/274.html
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-feed: Couldn't find any feeds.
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9090-TCP:V=7.95%I=7%D=6/15%Time=684E82A4%P=x86_64-apple-darwin23.6.
SF:0%r(GetRequest,9F,"HTTP/1\.0\x20401\x20Unauthorized\r\nContent-Type:\x2
SF:0application/json\r\nVary:\x20Origin\r\nDate:\x20Sun,\x2015\x20Jun\x202
SF:025\x2008:21:56\x20GMT\r\nContent-Length:\x2027\r\n\r\n{\"message\":\"U
SF:nauthorized\"}\n")%r(SqueezeCenter_CLI,67,"HTTP/1\.1\x20400\x20Bad\x20R
SF:equest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\
SF:x20close\r\n\r\n400\x20Bad\x20Request")%r(GenericLines,67,"HTTP/1\.1\x2
SF:0400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8
SF:\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,7
SF:5,"HTTP/1\.0\x20405\x20Method\x20Not\x20Allowed\r\nAllow:\x20GET\r\nVar
SF:y:\x20Origin\r\nDate:\x20Sun,\x2015\x20Jun\x202025\x2008:22:11\x20GMT\r
SF:\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20
SF:Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConn
SF:ection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x2
SF:0400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8
SF:\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(SSLSessionReq
SF:,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;
SF:\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request"
SF:)%r(FourOhFourRequest,BE,"HTTP/1\.0\x20404\x20Not\x20Found\r\nContent-T
SF:ype:\x20text/plain;\x20charset=utf-8\r\nVary:\x20Origin\r\nX-Content-Ty
SF:pe-Options:\x20nosniff\r\nDate:\x20Sun,\x2015\x20Jun\x202025\x2008:22:2
SF:6\x20GMT\r\nContent-Length:\x2019\r\n\r\n404\x20page\x20not\x20found\n"
SF:)%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(SIPOptions,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nC
SF:ontent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\
SF:n\r\n400\x20Bad\x20Request")%r(Socks5,67,"HTTP/1\.1\x20400\x20Bad\x20Re
SF:quest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x
SF:20close\r\n\r\n400\x20Bad\x20Request")%r(OfficeScan,A3,"HTTP/1\.1\x2040
SF:0\x20Bad\x20Request:\x20missing\x20required\x20Host\x20header\r\nConten
SF:t-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n
SF:400\x20Bad\x20Request:\x20missing\x20required\x20Host\x20header");

Read data files from: /usr/local/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jun 15 16:23:03 2025 -- 1 IP address (1 host up) scanned in 73.36 seconds

```
