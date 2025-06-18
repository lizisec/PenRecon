```bash
nmap -vv --reason -Pn -T4 -sV -p 3306 --script="banner,(mysql* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp3306/tcp_3306_mysql_nmap.txt" -oX "/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp3306/xml/tcp_3306_mysql_nmap.xml" localhost
```

[/Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp3306/tcp_3306_mysql_nmap.txt](file:///Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp3306/tcp_3306_mysql_nmap.txt):

```
# Nmap 7.95 scan initiated Sun Jun 15 16:21:49 2025 as: nmap -vv --reason -Pn -T4 -sV -p 3306 "--script=banner,(mysql* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN /Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp3306/tcp_3306_mysql_nmap.txt -oX /Users/lizi/Desktop/PenRecon/web-backend/results/localhost/scans/tcp3306/xml/tcp_3306_mysql_nmap.xml localhost
Warning: Hostname localhost resolves to 2 IPs. Using 127.0.0.1.
Nmap scan report for localhost (127.0.0.1)
Host is up, received user-set (0.00012s latency).
Other addresses for localhost (not scanned): ::1
Scanned at 2025-06-15 16:21:49 CST for 21s

PORT     STATE SERVICE REASON  VERSION
3306/tcp open  mysql?  syn-ack
| ssl-enum-ciphers: 
|   TLSv1.2: 
|     ciphers: 
|       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (secp256r1) - A
|       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (secp256r1) - A
|       TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (secp256r1) - A
|       TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (dh 2048) - A
|       TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (dh 2048) - A
|       TLS_DHE_RSA_WITH_AES_256_CCM (dh 2048) - A
|       TLS_DHE_RSA_WITH_AES_128_CCM (dh 2048) - A
|       TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (dh 2048) - A
|     compressors: 
|       NULL
|     cipher preference: server
|   TLSv1.3: 
|     ciphers: 
|       TLS_AKE_WITH_AES_128_GCM_SHA256 (secp256r1) - A
|       TLS_AKE_WITH_AES_256_GCM_SHA384 (secp256r1) - A
|       TLS_AKE_WITH_CHACHA20_POLY1305_SHA256 (secp256r1) - A
|       TLS_AKE_WITH_AES_128_CCM_SHA256 (secp256r1) - A
|     cipher preference: server
|_  least strength: A
|_ssl-date: TLS randomness does not represent time
| banner: I\x00\x00\x00\x0A9.3.0\x00\xAC\x01\x00\x00elL"!\x16*?\x00\xFF\x
| FF\xFF\x02\x00\xFF\xDF\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00m5V'\
|_x0B\x0E\x1FO"aoi\x00caching_sha2_password\x00
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
|   Thread ID: 469
|   Capabilities flags: 65535
|   Some Capabilities: LongPassword, IgnoreSigpipes, FoundRows, Speaks41ProtocolOld, Support41Auth, SupportsCompression, ConnectWithDatabase, IgnoreSpaceBeforeParenthesis, SupportsTransactions, ODBCClient, InteractiveClient, DontAllowDatabaseTableColumn, Speaks41ProtocolNew, SupportsLoadDataLocal, LongColumnFlag, SwitchToSSLAfterHandshake, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: jI!17E2JYWo\x05GYA\x0B 'u@
|_  Auth Plugin Name: caching_sha2_password
| fingerprint-strings: 
|   DNSStatusRequestTCP: 
|     9.3.0
|     )Rmf
|     *Mt#
|     caching_sha2_password
|     #08S01Got packets out of order
|   DNSVersionBindReqTCP: 
|     9.3.0
|     caching_sha2_password
|     #08S01Got packets out of order
|   GenericLines: 
|     9.3.0
|     elL"!
|     m5V'
|     O"aoi
|     caching_sha2_password
|     #08S01Got packets out of order
|   GetRequest: 
|     9.3.0
|     sz^o
|     oNO))rdIV|o;
|     caching_sha2_password
|     #08S01Got packets out of order
|   HTTPOptions: 
|     9.3.0
|     <QBm
|     _q&Q5c&
|     caching_sha2_password
|     #08S01Got packets out of order
|   Help: 
|     9.3.0
|     T:N1=
|     caching_sha2_password
|     #08S01Got packets out of order
|   NULL: 
|     9.3.0
|     elL"!
|     m5V'
|     O"aoi
|     caching_sha2_password
|   RPCCheck: 
|     9.3.0
|     'z5{
|     m/l{<+I;
|     caching_sha2_password
|     #08S01Got packets out of order
|   RTSPRequest: 
|     9.3.0
|     P}.P
|     xm=1
|     caching_sha2_password
|     #08S01Got packets out of order
|   SSLSessionReq: 
|     9.3.0
|     9XBbseg-
|     ]2i]
|     9J:T*I"
|     caching_sha2_password
|_    #08S01Got packets out of order
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.95%I=7%D=6/15%Time=684E82A3%P=x86_64-apple-darwin23.6.
SF:0%r(NULL,4D,"I\0\0\0\n9\.3\.0\0\xac\x01\0\0elL\"!\x16\*\?\0\xff\xff\xff
SF:\x02\0\xff\xdf\x15\0\0\0\0\0\0\0\0\0\0m5V'\x0b\x0e\x1fO\"aoi\0caching_s
SF:ha2_password\0")%r(GenericLines,72,"I\0\0\0\n9\.3\.0\0\xac\x01\0\0elL\"
SF:!\x16\*\?\0\xff\xff\xff\x02\0\xff\xdf\x15\0\0\0\0\0\0\0\0\0\0m5V'\x0b\x
SF:0e\x1fO\"aoi\0caching_sha2_password\0!\0\0\x01\xff\x84\x04#08S01Got\x20
SF:packets\x20out\x20of\x20order")%r(GetRequest,72,"I\0\0\0\n9\.3\.0\0\xad
SF:\x01\0\0g-0\x0csz\^o\0\xff\xff\xff\x02\0\xff\xdf\x15\0\0\0\0\0\0\0\0\0\
SF:0oNO\)\)rdIV\|o;\0caching_sha2_password\0!\0\0\x01\xff\x84\x04#08S01Got
SF:\x20packets\x20out\x20of\x20order")%r(HTTPOptions,72,"I\0\0\0\n9\.3\.0\
SF:0\xae\x01\0\0<QBm\x0fqO8\0\xff\xff\xff\x02\0\xff\xdf\x15\0\0\0\0\0\0\0\
SF:0\0\0\x03_q&Q5c&\x187/b\0caching_sha2_password\0!\0\0\x01\xff\x84\x04#0
SF:8S01Got\x20packets\x20out\x20of\x20order")%r(RTSPRequest,72,"I\0\0\0\n9
SF:\.3\.0\0\xaf\x01\0\0;\x0cP}\.P\x1a%\0\xff\xff\xff\x02\0\xff\xdf\x15\0\0
SF:\0\0\0\0\0\0\0\0Q\x12xm=1\x1e_\x03\"L'\0caching_sha2_password\0!\0\0\x0
SF:1\xff\x84\x04#08S01Got\x20packets\x20out\x20of\x20order")%r(RPCCheck,72
SF:,"I\0\0\0\n9\.3\.0\0\xb0\x01\0\0'z5{\x14`ll\0\xff\xff\xff\x02\0\xff\xdf
SF:\x15\0\0\0\0\0\0\0\0\0\0s\x1eP\x06m/l{<\+I;\0caching_sha2_password\0!\0
SF:\0\x01\xff\x84\x04#08S01Got\x20packets\x20out\x20of\x20order")%r(DNSVer
SF:sionBindReqTCP,72,"I\0\0\0\n9\.3\.0\0\xb1\x01\0\0,\)\x1fzXX\x03j\0\xff\
SF:xff\xff\x02\0\xff\xdf\x15\0\0\0\0\0\0\0\0\0\x005\t3x\x13'1U\x0esS2\0cac
SF:hing_sha2_password\0!\0\0\x01\xff\x84\x04#08S01Got\x20packets\x20out\x2
SF:0of\x20order")%r(DNSStatusRequestTCP,72,"I\0\0\0\n9\.3\.0\0\xb2\x01\0\0
SF:\)Rmf\x03\x1caV\0\xff\xff\xff\x02\0\xff\xdf\x15\0\0\0\0\0\0\0\0\0\0\x05
SF:\x1e\n-\x1b\*Mt#\x13oN\0caching_sha2_password\0!\0\0\x01\xff\x84\x04#08
SF:S01Got\x20packets\x20out\x20of\x20order")%r(Help,72,"I\0\0\0\n9\.3\.0\0
SF:\xb3\x01\0\0z3/\x0c\x04\x02=;\0\xff\xff\xff\x02\0\xff\xdf\x15\0\0\0\0\0
SF:\0\0\0\0\0\(\x1eIN\^\x03\x0cT:N1=\0caching_sha2_password\0!\0\0\x01\xff
SF:\x84\x04#08S01Got\x20packets\x20out\x20of\x20order")%r(SSLSessionReq,72
SF:,"I\0\0\0\n9\.3\.0\0\xb4\x01\0\x009XBbseg-\0\xff\xff\xff\x02\0\xff\xdf\
SF:x15\0\0\0\0\0\0\0\0\0\0\]2i\]\n9J:T\*I\"\0caching_sha2_password\0!\0\0\
SF:x01\xff\x84\x04#08S01Got\x20packets\x20out\x20of\x20order");

Read data files from: /usr/local/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jun 15 16:22:10 2025 -- 1 IP address (1 host up) scanned in 21.40 seconds

```
