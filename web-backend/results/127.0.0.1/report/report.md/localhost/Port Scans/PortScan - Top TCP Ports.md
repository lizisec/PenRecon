```bash
nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -oN "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/_quick_tcp_nmap.txt" -oX "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/xml/_quick_tcp_nmap.xml" localhost
```

[/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/_quick_tcp_nmap.txt](file:///Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/_quick_tcp_nmap.txt):

```
# Nmap 7.95 scan initiated Sun Jun 15 16:16:00 2025 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -oN /Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/_quick_tcp_nmap.txt -oX /Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/xml/_quick_tcp_nmap.xml localhost
Warning: Hostname localhost resolves to 2 IPs. Using 127.0.0.1.
Nmap scan report for localhost (127.0.0.1)
Host is up, received user-set (0.00029s latency).
Other addresses for localhost (not scanned): ::1
Scanned at 2025-06-15 16:16:00 CST for 349s
Not shown: 994 closed tcp ports (conn-refused)
PORT     STATE SERVICE       REASON  VERSION
445/tcp  open  microsoft-ds? syn-ack
3306/tcp open  mysql?        syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP: 
|     9.3.0
|     fdD:
|     F4TX
|     5s=e
|     caching_sha2_password
|     #08S01Got packets out of order
|   DNSVersionBindReqTCP: 
|     9.3.0
|     S1>D
|     caching_sha2_password
|     #08S01Got packets out of order
|   GenericLines: 
|     9.3.0
|     FP^6gy1
|     /Vry
|     caching_sha2_password
|     #08S01Got packets out of order
|   GetRequest: 
|     9.3.0
|     M7s:nv
|     caching_sha2_password
|     #08S01Got packets out of order
|   HTTPOptions: 
|     9.3.0
|     -w1d
|     \x1f#
|     yZ5y'
|     caching_sha2_password
|     #08S01Got packets out of order
|   Hello: 
|     9.3.0
|     mmUL
|     caching_sha2_password
|     #08S01Got packets out of order
|   Help: 
|     9.3.0
|     caching_sha2_password
|     #08S01Got packets out of order
|   NULL: 
|     9.3.0
|     FP^6gy1
|     /Vry
|     caching_sha2_password
|   RPCCheck: 
|     9.3.0
|     2>RD
|     VX7]#sqk
|     caching_sha2_password
|     #08S01Got packets out of order
|   RTSPRequest: 
|     9.3.0
|     5yHY
|     caching_sha2_password
|_    #08S01Got packets out of order
| ssl-cert: Subject: commonName=MySQL_Server_9.3.0_Auto_Generated_Server_Certificate
| Issuer: commonName=MySQL_Server_9.3.0_Auto_Generated_CA_Certificate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-05-25T14:26:33
| Not valid after:  2035-05-23T14:26:33
| MD5:   bf95:9e10:96e8:94b7:ef38:0f1c:d8c2:5ecc
| SHA-1: 73a6:e7c7:0def:22b9:c02d:7c29:497a:3ff6:bf9e:fcf7
| -----BEGIN CERTIFICATE-----
| MIIDBTCCAe2gAwIBAgIBAjANBgkqhkiG9w0BAQsFADA7MTkwNwYDVQQDDDBNeVNR
| TF9TZXJ2ZXJfOS4zLjBfQXV0b19HZW5lcmF0ZWRfQ0FfQ2VydGlmaWNhdGUwHhcN
| MjUwNTI1MTQyNjMzWhcNMzUwNTIzMTQyNjMzWjA/MT0wOwYDVQQDDDRNeVNRTF9T
| ZXJ2ZXJfOS4zLjBfQXV0b19HZW5lcmF0ZWRfU2VydmVyX0NlcnRpZmljYXRlMIIB
| IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmy1yda/6EQRklbKpDkDfTj7s
| AqFfl+yjRkSKrWXEJD7xaWqw+Lq4dIr9olcBLGMsSBN/m5cmmrnnPYgVKMIC+F5d
| W48ZdF0JB610YVjyOuuMUsV93BcGxHWT8pM8wDBnpXwiTrOw+8Cov9ux69HqrYD8
| DwRJv5VHZ63+adaQXhD6j0pEDV1+fGg2BzEuHJ0ETa/SwAfwaqiGHRwrSMilV3ca
| oLk9jVZJRkXyAFZvcN5W/J3OZZdldGsuqOzXIrQMNDKPyAl/L5NRwnC4JfQbA7Tp
| Z6QR/b+Cj8TOCn3t4epKJJ91EjuWDwSAI1ClvT8/rReatDFSJS2mF/9yTBCAQwID
| AQABoxAwDjAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQBMFRCb3eCo
| y4vRTXmITeOfu2fMoYutT4R5Awy4+6GnwEyXlf1Czd2hyH7NkvqRcOWlf2hPBI0V
| 0rmC0FILFBcJXePMpnR5UQqmzLKLtzA02xyn9LJJi4CXre39RsN59gbUvbL5hcAp
| hYHG4gsvH2eUXI9PvkW4pni2hCqJg9V1NEUDN5lES3/xOXFZF1qFrZ5Ev3QsPEzy
| KfOcPA78I8DYcPlOMm05NQ3Pp6TsAWycbPURSnyh20IrrB0TMccfGHDhQiX8FbxL
| le3jGgvd1WCoeiUQd16+WRWIctvHg0mX/8Z77gOmazdpYSX1e5HV5pQOvYVYTn75
| 0xPuB6n6lFT+
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| mysql-info: 
|   Protocol: 10
|   Version: 9.3.0
|   Thread ID: 414
|   Capabilities flags: 65535
|   Some Capabilities: SupportsCompression, ODBCClient, Support41Auth, DontAllowDatabaseTableColumn, SupportsTransactions, Speaks41ProtocolOld, SwitchToSSLAfterHandshake, FoundRows, LongColumnFlag, IgnoreSigpipes, LongPassword, IgnoreSpaceBeforeParenthesis, SupportsLoadDataLocal, Speaks41ProtocolNew, ConnectWithDatabase, InteractiveClient, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: Q
| \x15u\x13.\x157 DZ>i\x15ZReAJ\x1A
|_  Auth Plugin Name: caching_sha2_password
4001/tcp open  ssl/newoak?   syn-ack
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest, OfficeScan, apple-iphoto, docker, hazelcast-http, metasploit-msgrpc: 
|     HTTP/1.1 200 OK
|     Connection: close
|     Content-Length: 26
|     Content-Type: application/json
|     {"code":0,"msg":"success"}
|   HTTPOptions: 
|     HTTP/1.1 204 No Content
|_    Connection: close
| ssl-cert: Subject: commonName=localhost.ptlogin2.qq.com/organizationName=Shenzhen Tencent Computer Systems Company Limited/stateOrProvinceName=Guangdong Province/countryName=CN/localityName=Shenzhen
| Subject Alternative Name: DNS:localhost.ptlogin2.qq.com, DNS:localhost.ptlogin2.tencent.com, DNS:localhost.ptlogin2.tenpay.com, DNS:localhost.ptlogin2.weiyun.com
| Issuer: commonName=DigiCert Secure Site OV G2 TLS CN RSA4096 SHA256 2022 CA1/organizationName=DigiCert, Inc./countryName=US
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-05-16T00:00:00
| Not valid after:  2026-06-16T23:59:59
| MD5:   431b:3ac6:15fc:3330:b0a6:9bc6:485e:4a5a
| SHA-1: b87f:fac8:3152:2e22:2c12:249b:f5d7:bd3e:1678:f0bd
| -----BEGIN CERTIFICATE-----
| MIIITTCCBjWgAwIBAgIQBsaOEw+pe7gmor+3G0F51jANBgkqhkiG9w0BAQsFADBq
| MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQjBABgNVBAMT
| OURpZ2lDZXJ0IFNlY3VyZSBTaXRlIE9WIEcyIFRMUyBDTiBSU0E0MDk2IFNIQTI1
| NiAyMDIyIENBMTAeFw0yNTA1MTYwMDAwMDBaFw0yNjA2MTYyMzU5NTlaMIGdMQsw
| CQYDVQQGEwJDTjEbMBkGA1UECBMSR3Vhbmdkb25nIFByb3ZpbmNlMREwDwYDVQQH
| EwhTaGVuemhlbjE6MDgGA1UEChMxU2hlbnpoZW4gVGVuY2VudCBDb21wdXRlciBT
| eXN0ZW1zIENvbXBhbnkgTGltaXRlZDEiMCAGA1UEAxMZbG9jYWxob3N0LnB0bG9n
| aW4yLnFxLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMVUn66D
| pqds9pYChwVaPiXeCeC5tdSNewCJilsBJygFFDFYH6gCBui+5H9j0HaZ5Obofe70
| 5QGJBqeZCJDELDYh3+lAyPqx+858eMvy2Kucp1RcPCG4qDAhRaOoRafaxmDFiemQ
| 2vZ4wqJ9q0Zxnm3iT5otZGgKehnQByGZBKaYchFGA0Tsz0hoX19bfT7Fssh2nFsm
| 8/Mil9t+65fpBqq+YpKpd/AlNXI2yrwBl7sp18KfB7aPHFLqIOzM/87k+jEUXcUS
| gnIRNih/c103TD+pg34VoHJHZAWy7POE90ODs9XcCeURP1hJDd/XC6nKJwEECLcv
| 7eV5rdL1zsrBbg8CAwEAAaOCA7kwggO1MB8GA1UdIwQYMBaAFCsjFoEbR4mKkHrs
| 6DLUbI5y+c4lMB0GA1UdDgQWBBSfajRtiSQox5N9juvvIoa4eyESqjCBggYDVR0R
| BHsweYIZbG9jYWxob3N0LnB0bG9naW4yLnFxLmNvbYIebG9jYWxob3N0LnB0bG9n
| aW4yLnRlbmNlbnQuY29tgh1sb2NhbGhvc3QucHRsb2dpbjIudGVucGF5LmNvbYId
| bG9jYWxob3N0LnB0bG9naW4yLndlaXl1bi5jb20wPgYDVR0gBDcwNTAzBgZngQwB
| AgIwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMA4G
| A1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwWwYD
| VR0fBFQwUjBQoE6gTIZKaHR0cDovL2NybC5kaWdpY2VydC5jbi9EaWdpQ2VydFNl
| Y3VyZVNpdGVPVkcyVExTQ05SU0E0MDk2U0hBMjU2MjAyMkNBMS5jcmwwgZEGCCsG
| AQUFBwEBBIGEMIGBMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5kaWdpY2VydC5j
| bjBaBggrBgEFBQcwAoZOaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY24vRGlnaUNl
| cnRTZWN1cmVTaXRlT1ZHMlRMU0NOUlNBNDA5NlNIQTI1NjIwMjJDQTEuY3J0MAwG
| A1UdEwEB/wQCMAAwggF+BgorBgEEAdZ5AgQCBIIBbgSCAWoBaAB2AA5XlLzzrqk+
| MxssmQez95Dfm8I9cTIl3SGpJaxhxU4hAAABltgMm2EAAAQDAEcwRQIgYD2OOZf8
| rSwgrkiwu1K2XFwhSJKCYTi9EPCxuUBXoxcCIQD3ZpQEvbYJoby+Pmw6glIqt7Qo
| HwLK9n6zmfnc+sdwVgB1AGQRxGykEuyniRyiAi4AvKtPKAfUHjUnq+r+1QPJfc3w
| AAABltgMm48AAAQDAEYwRAIfSjH0cEx+wD3Ill2ATKmqHNCexk09PgxEaMxWuIdk
| ewIhAM3NCqx/eOJW4mK/3F2mYeL6fK48LwW7BaeuCWnF1XLpAHcASZybad4dfOz8
| Nt7Nh2SmuFuvCoeAGdFVUvvp6ynd+MMAAAGW2AybnAAABAMASDBGAiEAvC6WN5C5
| sefDIblHL9zdQ+Rq5+kPvr5PqnQPmWRCzTICIQD/OovsOzW/+PEEhNx6Lthp0wLb
| NWgXFPfCQATqAuaPuTANBgkqhkiG9w0BAQsFAAOCAgEAjSJFXm9gcJ+7wq0+66Wn
| V6BKuMN6Cygi0YlK/t7i+pOcIu7mtqO/EZo5E2BRYqdiYRprVEZLe78j4hSjL7UV
| U0QCqUlhBumhIYzfkir0d6ErC+H1PTBhKA0KIk+JZUm5unTfCr14fJZ/uSjB/d16
| S5EQxNa3FAv2hpXLsMZCFkxQz8m9RNji0TeTZ85wy5Y0EChzSObVPjgHd6tTubJY
| J/4kKsI4bNdhkP0g3LyO4yEIrf4U2DKRV33GGflOVSX3dYp+XxUF5fgzVuw55xcf
| hlnOaiUmkr0JBmHOX0lOwf5Lp4s/l2KleFLxSszXcu9a9wKyeOcz9G2mwMn02jb8
| S10BBwQyFfGu3eKGT+NyJJs3+ZrKeFIV/zmgr9bDZOx6kiKScM8AfoMXuhtEHqgD
| yHgVuUGEEI32MCBOpBiBFER0++CUR5tdW7+bw163gBFb083Ddvc4QnnKWX9GQ+Bo
| WG+UsVHva2LF1J4cE0ufdAIuQ2i5CBGzo80MUnil4o+yMpzIdfFD3C+T16cy6H2N
| gGF3CIcfNLgy2acontUsLCaM182No3+4deelacqqqQJ7FM5SBil9wGCF2JNoXUs4
| /cd2f6FXb6Er+Vo4FfhoI1ieLp+MqkIG+Jd7rZN3fDCilo9H9Lxnpt65mbP/aIES
| SG5Z6MBpAvhMggOgeubO6zQ=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
8000/tcp open  http          syn-ack Uvicorn
|_http-title: Site doesn't have a title (application/json).
|_http-cors: GET POST PUT DELETE OPTIONS PATCH
|_http-server-header: uvicorn
8021/tcp open  tcpwrapped    syn-ack
9090/tcp open  http          syn-ack Golang net/http server
| http-methods: 
|_  Supported Methods: GET
|_http-cors: GET POST PUT DELETE OPTIONS PATCH
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 Not Found
|     Content-Type: text/plain; charset=utf-8
|     Vary: Origin
|     X-Content-Type-Options: nosniff
|     Date: Sun, 15 Jun 2025 08:16:56 GMT
|     Content-Length: 19
|     page not found
|   GenericLines, Hello, Help, Kerberos, RTSPRequest, SSLSessionReq, SSLv23SessionReq, SqueezeCenter_CLI, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 401 Unauthorized
|     Content-Type: application/json
|     Vary: Origin
|     Date: Sun, 15 Jun 2025 08:16:06 GMT
|     Content-Length: 27
|     {"message":"Unauthorized"}
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Allow: GET
|     Vary: Origin
|     Date: Sun, 15 Jun 2025 08:16:31 GMT
|_    Content-Length: 0
|_http-title: Site doesn't have a title (application/json).
3 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3306-TCP:V=7.95%I=9%D=6/15%Time=684E8146%P=x86_64-apple-darwin23.6.
SF:0%r(NULL,4D,"I\0\0\0\n9\.3\.0\0\xd4\0\0\0\rFP\^6gy1\0\xff\xff\xff\x02\0
SF:\xff\xdf\x15\0\0\0\0\0\0\0\0\0\0l\x1e/Vry\x1a\x13T0\x18\x1c\0caching_sh
SF:a2_password\0")%r(GenericLines,72,"I\0\0\0\n9\.3\.0\0\xd4\0\0\0\rFP\^6g
SF:y1\0\xff\xff\xff\x02\0\xff\xdf\x15\0\0\0\0\0\0\0\0\0\0l\x1e/Vry\x1a\x13
SF:T0\x18\x1c\0caching_sha2_password\0!\0\0\x01\xff\x84\x04#08S01Got\x20pa
SF:ckets\x20out\x20of\x20order")%r(GetRequest,72,"I\0\0\0\n9\.3\.0\0\xd6\0
SF:\0\x006}O\x1d&\x01\x1f\)\0\xff\xff\xff\x02\0\xff\xdf\x15\0\0\0\0\0\0\0\
SF:0\0\0H5'\x0cj\x1dM7s:nv\0caching_sha2_password\0!\0\0\x01\xff\x84\x04#0
SF:8S01Got\x20packets\x20out\x20of\x20order")%r(HTTPOptions,72,"I\0\0\0\n9
SF:\.3\.0\0\xd7\0\0\0&\x02\x04-w1d\x14\0\xff\xff\xff\x02\0\xff\xdf\x15\0\0
SF:\0\0\0\0\0\0\0\0\\\x1f#\x1fyZ5y'\x0f_Z\0caching_sha2_password\0!\0\0\x0
SF:1\xff\x84\x04#08S01Got\x20packets\x20out\x20of\x20order")%r(RTSPRequest
SF:,72,"I\0\0\0\n9\.3\.0\0\xd8\0\0\0P\(O\x08D\x0c\x03S\0\xff\xff\xff\x02\0
SF:\xff\xdf\x15\0\0\0\0\0\0\0\0\0\0',p\x0b5yHY\x18'\x0f\x06\0caching_sha2_
SF:password\0!\0\0\x01\xff\x84\x04#08S01Got\x20packets\x20out\x20of\x20ord
SF:er")%r(RPCCheck,72,"I\0\0\0\n9\.3\.0\0\xd9\0\0\0_f\(\x072>RD\0\xff\xff\
SF:xff\x02\0\xff\xdf\x15\0\0\0\0\0\0\0\0\0\0VX7\]#sqk\x1a\x1fOm\0caching_s
SF:ha2_password\0!\0\0\x01\xff\x84\x04#08S01Got\x20packets\x20out\x20of\x2
SF:0order")%r(DNSVersionBindReqTCP,72,"I\0\0\0\n9\.3\.0\0\xda\0\0\0S1>D\x1
SF:di\x0b_\0\xff\xff\xff\x02\0\xff\xdf\x15\0\0\0\0\0\0\0\0\0\0k\x02\x13m>\
SF:x7f\x11cqw\x7f\x20\0caching_sha2_password\0!\0\0\x01\xff\x84\x04#08S01G
SF:ot\x20packets\x20out\x20of\x20order")%r(DNSStatusRequestTCP,72,"I\0\0\0
SF:\n9\.3\.0\0\xdb\0\0\0fdD:\r\x08\x11A\0\xff\xff\xff\x02\0\xff\xdf\x15\0\
SF:0\0\0\0\0\0\0\0\0\x05F4TX\x04\n5s=e\x01\0caching_sha2_password\0!\0\0\x
SF:01\xff\x84\x04#08S01Got\x20packets\x20out\x20of\x20order")%r(Hello,72,"
SF:I\0\0\0\n9\.3\.0\0\xdc\0\0\0W\x1cr\"3\x0f<X\0\xff\xff\xff\x02\0\xff\xdf
SF:\x15\0\0\0\0\0\0\0\0\0\0mmUL\x07\x071\x04,\?\x15s\0caching_sha2_passwor
SF:d\0!\0\0\x01\xff\x84\x04#08S01Got\x20packets\x20out\x20of\x20order")%r(
SF:Help,72,"I\0\0\0\n9\.3\.0\0\xdd\0\0\0\x02Ba\x1e\x0fO&\?\0\xff\xff\xff\x
SF:02\0\xff\xdf\x15\0\0\0\0\0\0\0\0\0\x008,\+\x1f{\x11b\x7f\nq\"F\0caching
SF:_sha2_password\0!\0\0\x01\xff\x84\x04#08S01Got\x20packets\x20out\x20of\
SF:x20order");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4001-TCP:V=7.95%T=SSL%I=9%D=6/15%Time=684E8155%P=x86_64-apple-darwi
SF:n23.6.0%r(GetRequest,74,"HTTP/1\.1\x20200\x20OK\r\nConnection:\x20close
SF:\r\nContent-Length:\x2026\r\nContent-Type:\x20application/json\r\n\r\n{
SF:\"code\":0,\"msg\":\"success\"}")%r(HTTPOptions,2E,"HTTP/1\.1\x20204\x2
SF:0No\x20Content\r\nConnection:\x20close\r\n\r\n")%r(FourOhFourRequest,74
SF:,"HTTP/1\.1\x20200\x20OK\r\nConnection:\x20close\r\nContent-Length:\x20
SF:26\r\nContent-Type:\x20application/json\r\n\r\n{\"code\":0,\"msg\":\"su
SF:ccess\"}")%r(OfficeScan,74,"HTTP/1\.1\x20200\x20OK\r\nConnection:\x20cl
SF:ose\r\nContent-Length:\x2026\r\nContent-Type:\x20application/json\r\n\r
SF:\n{\"code\":0,\"msg\":\"success\"}")%r(apple-iphoto,74,"HTTP/1\.1\x2020
SF:0\x20OK\r\nConnection:\x20close\r\nContent-Length:\x2026\r\nContent-Typ
SF:e:\x20application/json\r\n\r\n{\"code\":0,\"msg\":\"success\"}")%r(meta
SF:sploit-msgrpc,74,"HTTP/1\.1\x20200\x20OK\r\nConnection:\x20close\r\nCon
SF:tent-Length:\x2026\r\nContent-Type:\x20application/json\r\n\r\n{\"code\
SF:":0,\"msg\":\"success\"}")%r(hazelcast-http,74,"HTTP/1\.1\x20200\x20OK\
SF:r\nConnection:\x20close\r\nContent-Length:\x2026\r\nContent-Type:\x20ap
SF:plication/json\r\n\r\n{\"code\":0,\"msg\":\"success\"}")%r(docker,74,"H
SF:TTP/1\.1\x20200\x20OK\r\nConnection:\x20close\r\nContent-Length:\x2026\
SF:r\nContent-Type:\x20application/json\r\n\r\n{\"code\":0,\"msg\":\"succe
SF:ss\"}");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port9090-TCP:V=7.95%I=9%D=6/15%Time=684E8146%P=x86_64-apple-darwin23.6.
SF:0%r(GetRequest,9F,"HTTP/1\.0\x20401\x20Unauthorized\r\nContent-Type:\x2
SF:0application/json\r\nVary:\x20Origin\r\nDate:\x20Sun,\x2015\x20Jun\x202
SF:025\x2008:16:06\x20GMT\r\nContent-Length:\x2027\r\n\r\n{\"message\":\"U
SF:nauthorized\"}\n")%r(SqueezeCenter_CLI,67,"HTTP/1\.1\x20400\x20Bad\x20R
SF:equest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\
SF:x20close\r\n\r\n400\x20Bad\x20Request")%r(GenericLines,67,"HTTP/1\.1\x2
SF:0400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8
SF:\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,7
SF:5,"HTTP/1\.0\x20405\x20Method\x20Not\x20Allowed\r\nAllow:\x20GET\r\nVar
SF:y:\x20Origin\r\nDate:\x20Sun,\x2015\x20Jun\x202025\x2008:16:31\x20GMT\r
SF:\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20
SF:Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConn
SF:ection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Hello,67,"HTTP/1\.1\x
SF:20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-
SF:8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Help,67,"HTT
SF:P/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20char
SF:set=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(SSLS
SF:essionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x20400\x20Bad\x20Reques
SF:t\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20cl
SF:ose\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,67,"HTTP/1\.1\x20400
SF:\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\n
SF:Connection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(SSLv23SessionReq,
SF:67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\
SF:x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")
SF:%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20
SF:text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\
SF:x20Request")%r(FourOhFourRequest,BE,"HTTP/1\.0\x20404\x20Not\x20Found\r
SF:\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nVary:\x20Origin\r\nX
SF:-Content-Type-Options:\x20nosniff\r\nDate:\x20Sun,\x2015\x20Jun\x202025
SF:\x2008:16:56\x20GMT\r\nContent-Length:\x2019\r\n\r\n404\x20page\x20not\
SF:x20found\n");

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 49055/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 43272/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 4348/udp): CLEAN (Failed to receive data)
|   Check 4 (port 17725/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: -4s
| smb2-security-mode: 
|   3:0:2: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-06-15T08:21:17
|_  start_date: N/A

Read data files from: /usr/local/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jun 15 16:21:49 2025 -- 1 IP address (1 host up) scanned in 349.19 seconds

```
