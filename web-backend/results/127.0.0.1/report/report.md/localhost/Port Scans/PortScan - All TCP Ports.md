```bash
nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/_full_tcp_nmap.txt" -oX "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/xml/_full_tcp_nmap.xml" localhost
```

[/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/_full_tcp_nmap.txt](file:///Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/_full_tcp_nmap.txt):

```
# Nmap 7.95 scan initiated Sun Jun 15 16:16:00 2025 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/_full_tcp_nmap.txt -oX /Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/xml/_full_tcp_nmap.xml localhost
Warning: Hostname localhost resolves to 2 IPs. Using 127.0.0.1.
Nmap scan report for localhost (127.0.0.1)
Host is up, received user-set (0.00044s latency).
Other addresses for localhost (not scanned): ::1
Scanned at 2025-06-15 16:16:00 CST for 362s
Not shown: 65524 closed tcp ports (conn-refused)
PORT      STATE SERVICE       REASON  VERSION
445/tcp   open  microsoft-ds? syn-ack
3306/tcp  open  mysql?        syn-ack
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
| mysql-info: 
|   Protocol: 10
|   Version: 9.3.0
|   Thread ID: 417
|   Capabilities flags: 65535
|   Some Capabilities: IgnoreSpaceBeforeParenthesis, Support41Auth, Speaks41ProtocolNew, ConnectWithDatabase, Speaks41ProtocolOld, SupportsTransactions, IgnoreSigpipes, SwitchToSSLAfterHandshake, DontAllowDatabaseTableColumn, LongPassword, InteractiveClient, LongColumnFlag, FoundRows, SupportsLoadDataLocal, SupportsCompression, ODBCClient, SupportsAuthPlugins, SupportsMultipleStatments, SupportsMultipleResults
|   Status: Autocommit
|   Salt: g1Bp>\x1A@[\x0DSF6Db\x01f,U!@
|_  Auth Plugin Name: caching_sha2_password
| fingerprint-strings: 
|   DNSStatusRequestTCP: 
|     9.3.0
|     s@I\0
|     c%j:7GEBHo7
|     caching_sha2_password
|     #08S01Got packets out of order
|   DNSVersionBindReqTCP: 
|     9.3.0
|     Z4oF
|     `565s
|     caching_sha2_password
|     #08S01Got packets out of order
|   GenericLines: 
|     9.3.0
|     uyCb
|     A#}2
|     caching_sha2_password
|     #08S01Got packets out of order
|   GetRequest: 
|     9.3.0
|     A%<r]M1a
|     r!S.
|     caching_sha2_password
|     #08S01Got packets out of order
|   HTTPOptions: 
|     9.3.0
|     ]Ijgkk{
|     caching_sha2_password
|     #08S01Got packets out of order
|   Hello: 
|     9.3.0
|     S.>G#^]
|     caching_sha2_password
|     #08S01Got packets out of order
|   Help: 
|     9.3.0
|     qJXqP
|     caching_sha2_password
|     #08S01Got packets out of order
|   NULL: 
|     9.3.0
|     uyCb
|     A#}2
|     caching_sha2_password
|   RPCCheck: 
|     9.3.0
|     qlU%
|     hMxqVkFP
|     caching_sha2_password
|     #08S01Got packets out of order
|   RTSPRequest: 
|     9.3.0
|     gS:ul!F
|     cFKOJsxI
|     caching_sha2_password
|_    #08S01Got packets out of order
|_ssl-date: TLS randomness does not represent time
4001/tcp  open  ssl/newoak?   syn-ack
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
|_ssl-date: TLS randomness does not represent time
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
4301/tcp  open  ssl/d-data?   syn-ack
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
4310/tcp  open  mirrtex?      syn-ack
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Length: 360
|     ,+m! 
|     Q[a9P1u
|     s%h"F
|     YG%La"
|     G>kDe
|     MfvC
|     \xae%.
|     ~r.7
|     c6!%
|     rg1TG
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Content-Length: 360
|     1!C;
|_    YRt"
7890/tcp  open  socks5        syn-ack (No authentication; connection failed)
| socks-auth-info: 
|   No authentication
|   No authentication
|_  No authentication
| socks-open-proxy: 
|   status: open
|   versions: 
|     socks4
|_    socks5
8000/tcp  open  http          syn-ack Uvicorn
|_http-title: Site doesn't have a title (application/json).
|_http-server-header: uvicorn
|_http-cors: GET POST PUT DELETE OPTIONS PATCH
8021/tcp  open  tcpwrapped    syn-ack
9090/tcp  open  http          syn-ack Golang net/http server
|_http-cors: GET POST PUT DELETE OPTIONS PATCH
| http-methods: 
|_  Supported Methods: GET
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 Not Found
|     Content-Type: text/plain; charset=utf-8
|     Vary: Origin
|     X-Content-Type-Options: nosniff
|     Date: Sun, 15 Jun 2025 08:17:05 GMT
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
|     Date: Sun, 15 Jun 2025 08:16:15 GMT
|     Content-Length: 27
|     {"message":"Unauthorized"}
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Allow: GET
|     Vary: Origin
|     Date: Sun, 15 Jun 2025 08:16:40 GMT
|_    Content-Length: 0
|_http-title: Site doesn't have a title (application/json).
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
9210/tcp  open  oma-mlp?      syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Hello, Help, Kerberos, RPCCheck, SSLSessionReq, SSLv23SessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Content-Type: application/json
|     Date: Sun, 15 Jun 2025 08:16:20 GMT
|     Connection: close
|     eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlcnJDb2RlIjo0MDAxLCJlcnJNc2ciOiLor7fmsYLmlbDmja7nu5PmnoTplJnor68iLCJwb3J0Ijo5MjEwLCJpc09ubHlHdWlsZCI6ZmFsc2UsImlhdCI6MTc0OTk3NTM4MH0.S7-t_i97aZFfR8k57JkKSaHGMJj45IhwQbj3N_aw8HE
|   HTTPOptions, RTSPRequest: 
|     HTTP/1.1 200 OK
|     Content-Type: application/json
|     Date: Sun, 15 Jun 2025 08:16:20 GMT
|     Connection: close
|_    eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlcnJDb2RlIjo0MDAyLCJlcnJNc2ciOiLor7fmsYLmlrnms5XkuI3mlK_mjIEiLCJwb3J0Ijo5MjEwLCJpc09ubHlHdWlsZCI6ZmFsc2UsImlhdCI6MTc0OTk3NTM4MH0.ZuPk4J3m-mN6aUfQMSvlm-OfrHX58o-46UufV_E7ZKg
33060/tcp open  mysqlx        syn-ack MySQL X protocol listener
5 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3306-TCP:V=7.95%I=9%D=6/15%Time=684E814F%P=x86_64-apple-darwin23.6.
SF:0%r(NULL,4D,"I\0\0\0\n9\.3\.0\0\xe9\0\0\x003\x077\ruyCb\0\xff\xff\xff\x
SF:02\0\xff\xdf\x15\0\0\0\0\0\0\0\0\0\0&y{\x08\x07U\x12A#}2\x0e\0caching_s
SF:ha2_password\0")%r(GenericLines,72,"I\0\0\0\n9\.3\.0\0\xe9\0\0\x003\x07
SF:7\ruyCb\0\xff\xff\xff\x02\0\xff\xdf\x15\0\0\0\0\0\0\0\0\0\0&y{\x08\x07U
SF:\x12A#}2\x0e\0caching_sha2_password\0!\0\0\x01\xff\x84\x04#08S01Got\x20
SF:packets\x20out\x20of\x20order")%r(GetRequest,72,"I\0\0\0\n9\.3\.0\0\xf9
SF:\0\0\0A%<r\]M1a\0\xff\xff\xff\x02\0\xff\xdf\x15\0\0\0\0\0\0\0\0\0\0\]5\
SF:x02A\x12r!S\.\x03\x0fp\0caching_sha2_password\0!\0\0\x01\xff\x84\x04#08
SF:S01Got\x20packets\x20out\x20of\x20order")%r(HTTPOptions,72,"I\0\0\0\n9\
SF:.3\.0\0\xfa\0\0\0L\x10M\x06Z`\x05G\0\xff\xff\xff\x02\0\xff\xdf\x15\0\0\
SF:0\0\0\0\0\0\0\0\x7fs\x04u\x0e\]Ijgkk{\0caching_sha2_password\0!\0\0\x01
SF:\xff\x84\x04#08S01Got\x20packets\x20out\x20of\x20order")%r(RTSPRequest,
SF:72,"I\0\0\0\n9\.3\.0\0\xfb\0\0\0\x7fgS:ul!F\0\xff\xff\xff\x02\0\xff\xdf
SF:\x15\0\0\0\0\0\0\0\0\0\0\x0fcFKOJsxI\x7f~\x0c\0caching_sha2_password\0!
SF:\0\0\x01\xff\x84\x04#08S01Got\x20packets\x20out\x20of\x20order")%r(RPCC
SF:heck,72,"I\0\0\0\n9\.3\.0\0\xfc\0\0\0\x1b@\x02\x18qlU%\0\xff\xff\xff\x0
SF:2\0\xff\xdf\x15\0\0\0\0\0\0\0\0\0\0h\\MxqVkFP\x0c=/\0caching_sha2_passw
SF:ord\0!\0\0\x01\xff\x84\x04#08S01Got\x20packets\x20out\x20of\x20order")%
SF:r(DNSVersionBindReqTCP,72,"I\0\0\0\n9\.3\.0\0\xfd\0\0\0\x20Z4oF\x07v\x0
SF:3\0\xff\xff\xff\x02\0\xff\xdf\x15\0\0\0\0\0\0\0\0\0\0'6\x0ci\"/\x20`565
SF:s\0caching_sha2_password\0!\0\0\x01\xff\x84\x04#08S01Got\x20packets\x20
SF:out\x20of\x20order")%r(DNSStatusRequestTCP,72,"I\0\0\0\n9\.3\.0\0\xfe\0
SF:\0\0\+Kr\x19s@I\\\0\xff\xff\xff\x02\0\xff\xdf\x15\0\0\0\0\0\0\0\0\0\0\x
SF:01c%j:7GEBHo7\0caching_sha2_password\0!\0\0\x01\xff\x84\x04#08S01Got\x2
SF:0packets\x20out\x20of\x20order")%r(Hello,72,"I\0\0\0\n9\.3\.0\0\xff\0\0
SF:\0:\x1b6!\x167W\x1d\0\xff\xff\xff\x02\0\xff\xdf\x15\0\0\0\0\0\0\0\0\0\0
SF:S\.>G#\^\]\x0b\x06=\x01\x1b\0caching_sha2_password\0!\0\0\x01\xff\x84\x
SF:04#08S01Got\x20packets\x20out\x20of\x20order")%r(Help,72,"I\0\0\0\n9\.3
SF:\.0\0\0\x01\0\0dZl\x1c,s\x0fn\0\xff\xff\xff\x02\0\xff\xdf\x15\0\0\0\0\0
SF:\0\0\0\0\x002{\x02>;\t\x20qJXqP\0caching_sha2_password\0!\0\0\x01\xff\x
SF:84\x04#08S01Got\x20packets\x20out\x20of\x20order");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4001-TCP:V=7.95%T=SSL%I=9%D=6/15%Time=684E815E%P=x86_64-apple-darwi
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
SF-Port4310-TCP:V=7.95%I=9%D=6/15%Time=684E8154%P=x86_64-apple-darwin23.6.
SF:0%r(GetRequest,18E,"HTTP/1\.1\x20200\x20\r\nContent-Length:\x20360\r\n\
SF:r\n\xdeT\"\xd8\xd7f\xf9\+\xc9\r\x1e,\+m!\x20\0\0\x01J\0\0\x01P\x82\x15\
SF:xf7x{\xf1\x1d\xd0\x90\xe7\xb9\xaei\xe6u8\x0e\]\x01\xd0\xa7\xa6\x08\xfd\
SF:x96\x9d\xdc\xf3Q\[a9P1u\x8b\x0b\x03\x03\xf6\xd1U\xca\x95\xfc\xa7z\x99e\
SF:x97\xec\xb7\x15\xcfz~\xdfq\xf1z\x16\x81\x11\tV\xa4\xe7\xfel\xc8\xd9\xe4
SF:s%h\"F\x06U\xb9\xfe\)\x8db\x04\xfaYG%La\"\x9d\r\x0b\xa4`\x84G>kDe\xcdGp
SF:\xd0\x1e\x89y\x0f\xc8O\x0e\xce\xf2\x20MfvC\x91\xa1\x200c\xea\x04\xa4\xc
SF:5\x7f\xeb\xb5\t\xb3\xd4\\\xae%\.\xe5\xdb\x87!\x1cJ\r>6\xb5\xa4L\xa1\xad
SF:v\xc5\x0077\xbb\x13\x13\+\xe7\x85\x04\x93w\x17~r\.7\xc4\xa0\xbcJ\xd3PoG
SF:\xbe\(p\x86\x20n\xe1\x1b\xaa\xb8If\xd1\xa2\xc6\x1cbu\x12\xc8a\^\x90\x08
SF:\xe9\xf9Dg\x90z\x06\xdf\xae\xb3\)\x95\xbaZ\xc4\n\xbc\x19\xf0u\xfe~@\xe2
SF:\xac\xf9\r\xcc!\+\x90c6!%\x15y\x11ouB\xce\xce\|2\x94\x18\xc5\x87\xa4\xe
SF:4,\xc6\x87\xf4m\xd1\xc7\xc9\xd6\xa2\xd7\xf3y\xaa\x8aV\x8b\xf2!\xf7;3\x8
SF:2\xe4\+\x8a\x17\x0fG\x8f\xcc\t\xf3Ir\x83\xc0t\x0b\xbaB@\xbc\x95\xdf\x80
SF:\x94@\xcc\xf1\x88\x15\xaf\xc2\xa4<Q\xbe\(\xf7\xb5\xaa_\xf2rg1TG\x10:\xc
SF:0\xc7Y\xc0\xa2\x91\[\xa6\.")%r(HTTPOptions,18E,"HTTP/1\.1\x20200\x20\r\
SF:nContent-Length:\x20360\r\n\r\n\x0f\xf3\xea\x91\x8e\xf6\.\xf7G\xfc\*\0\
SF:xf8\x17M\x1e\0\0\x01J\0\0\x01P}b\xc6b\xde\xf9\xc0\x16\xde\xb5\x95\xa3\x
SF:9fZni\x0c\xdf{\x20'5_\x02\x93`\xe4\r\xaa\xb5\x0f\xaf\x97\x99\]m\^\x02\x
SF:945j9\x19p\xfa\+\xa4G\xefPt\xc9#\x1e\x1eh\x20\x06sM\xb4l8\x85\xff5\xe8&
SF:\xb5\x95\xa5ho\x8e\x93\x87\xc0\xea\xd5o\xc3\xa5\xd6\xe0\x987\r\xb8B\xa5
SF:v\(\xf5\x01\xd31!C;\xff\x92\xe4\x16\xa0xx\x97\xc3E;\$\xe9\x11\xfb\xc0\]
SF:@\nZ\xda\x02\xe0\xe3\xb3\xc9\x05\xcd\xa7-cH\xb0\x8a\x8ap\xed\xdcs\x1dN\
SF:xca\0\xa0\xb1g\?\x9c=\x04\xbe8\xf3<@\x82\x9d\(L\xc11\xa0\x8a\x86\xde\xc
SF:2\x8dTHt\xafv\xc7\xa7I\x02\x8e\x11\x1cOv\x11\xc3\xe6G\x81\xbaCO\xb5\[\+
SF:\xd8\$\xee>A\xb5\x8dh\x20P\xeb7_\|\xa1\xc7\x99\xe4\.\x95\x0c\xe9d\xa6\x
SF:0enn\(\xc7\x98R}\x98\xf7R\x83\x1c\x9e\0\xc5ke\xa4\xe3=\x15\xf2\xc4\x85\
SF:x8f\xf7\xd9\xdfUW3\xe9\xe8\x16\x18\xe9\xa1\xe4\xdf\xb1\xdd\x1e\x8b1\x01
SF:a\xbb\xaeS\xc7\xb6v\xe5k\xf9\xe1T\xe0\xed;J0\x18\x12g\x9cYRt\"\xd8\x14C
SF:w\?\xc9\x84\]\xc48#\xd9\xdc1\xcb\x17Wu\x88J\x13{}\xc8\xbbU\xd9~\xc7\x03
SF:\xb3\(\xee\t<\xb2\xd9u\xd7\xc6\xec\xe6\x94C\xc8\xb9W\x86P\]");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port9090-TCP:V=7.95%I=9%D=6/15%Time=684E814F%P=x86_64-apple-darwin23.6.
SF:0%r(GetRequest,9F,"HTTP/1\.0\x20401\x20Unauthorized\r\nContent-Type:\x2
SF:0application/json\r\nVary:\x20Origin\r\nDate:\x20Sun,\x2015\x20Jun\x202
SF:025\x2008:16:15\x20GMT\r\nContent-Length:\x2027\r\n\r\n{\"message\":\"U
SF:nauthorized\"}\n")%r(SqueezeCenter_CLI,67,"HTTP/1\.1\x20400\x20Bad\x20R
SF:equest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\
SF:x20close\r\n\r\n400\x20Bad\x20Request")%r(GenericLines,67,"HTTP/1\.1\x2
SF:0400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8
SF:\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,7
SF:5,"HTTP/1\.0\x20405\x20Method\x20Not\x20Allowed\r\nAllow:\x20GET\r\nVar
SF:y:\x20Origin\r\nDate:\x20Sun,\x2015\x20Jun\x202025\x2008:16:40\x20GMT\r
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
SF:\x2008:17:05\x20GMT\r\nContent-Length:\x2019\r\n\r\n404\x20page\x20not\
SF:x20found\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port9210-TCP:V=7.95%I=9%D=6/15%Time=684E8154%P=x86_64-apple-darwin23.6.
SF:0%r(GetRequest,143,"HTTP/1\.1\x20200\x20OK\r\nContent-Type:\x20applicat
SF:ion/json\r\nDate:\x20Sun,\x2015\x20Jun\x202025\x2008:16:20\x20GMT\r\nCo
SF:nnection:\x20close\r\n\r\neyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJlcnJ
SF:Db2RlIjo0MDAxLCJlcnJNc2ciOiLor7fmsYLmlbDmja7nu5PmnoTplJnor68iLCJwb3J0Ij
SF:o5MjEwLCJpc09ubHlHdWlsZCI6ZmFsc2UsImlhdCI6MTc0OTk3NTM4MH0\.S7-t_i97aZFf
SF:R8k57JkKSaHGMJj45IhwQbj3N_aw8HE")%r(HTTPOptions,13F,"HTTP/1\.1\x20200\x
SF:20OK\r\nContent-Type:\x20application/json\r\nDate:\x20Sun,\x2015\x20Jun
SF:\x202025\x2008:16:20\x20GMT\r\nConnection:\x20close\r\n\r\neyJhbGciOiJI
SF:UzI1NiIsInR5cCI6IkpXVCJ9\.eyJlcnJDb2RlIjo0MDAyLCJlcnJNc2ciOiLor7fmsYLml
SF:rnms5XkuI3mlK_mjIEiLCJwb3J0Ijo5MjEwLCJpc09ubHlHdWlsZCI6ZmFsc2UsImlhdCI6
SF:MTc0OTk3NTM4MH0\.ZuPk4J3m-mN6aUfQMSvlm-OfrHX58o-46UufV_E7ZKg")%r(RTSPRe
SF:quest,13F,"HTTP/1\.1\x20200\x20OK\r\nContent-Type:\x20application/json\
SF:r\nDate:\x20Sun,\x2015\x20Jun\x202025\x2008:16:20\x20GMT\r\nConnection:
SF:\x20close\r\n\r\neyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJlcnJDb2RlIjo0
SF:MDAyLCJlcnJNc2ciOiLor7fmsYLmlrnms5XkuI3mlK_mjIEiLCJwb3J0Ijo5MjEwLCJpc09
SF:ubHlHdWlsZCI6ZmFsc2UsImlhdCI6MTc0OTk3NTM4MH0\.ZuPk4J3m-mN6aUfQMSvlm-Ofr
SF:HX58o-46UufV_E7ZKg")%r(RPCCheck,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\
SF:r\nConnection:\x20close\r\n\r\n")%r(DNSVersionBindReqTCP,2F,"HTTP/1\.1\
SF:x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(DNSStatusR
SF:equestTCP,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20clos
SF:e\r\n\r\n")%r(Hello,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnectio
SF:n:\x20close\r\n\r\n")%r(Help,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n
SF:Connection:\x20close\r\n\r\n")%r(SSLSessionReq,2F,"HTTP/1\.1\x20400\x20
SF:Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(TerminalServerCookie
SF:,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n
SF:")%r(TLSSessionReq,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection
SF::\x20close\r\n\r\n")%r(SSLv23SessionReq,2F,"HTTP/1\.1\x20400\x20Bad\x20
SF:Request\r\nConnection:\x20close\r\n\r\n")%r(Kerberos,2F,"HTTP/1\.1\x204
SF:00\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n");

Host script results:
|_clock-skew: -11s
| smb2-time: 
|   date: 2025-06-15T08:21:17
|_  start_date: N/A
| smb2-security-mode: 
|   3:0:2: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 49055/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 43272/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 4348/udp): CLEAN (Failed to receive data)
|   Check 4 (port 17725/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

Read data files from: /usr/local/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jun 15 16:22:02 2025 -- 1 IP address (1 host up) scanned in 361.86 seconds

```
