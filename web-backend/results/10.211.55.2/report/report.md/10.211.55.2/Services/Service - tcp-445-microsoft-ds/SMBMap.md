```bash
smbmap -H 10.211.55.2 -P 445 2>&1
```

[/home/lizi/Desktop/myproj/PenRecon/web-backend/results/10.211.55.2/scans/tcp445/smbmap-share-permissions.txt](file:///home/lizi/Desktop/myproj/PenRecon/web-backend/results/10.211.55.2/scans/tcp445/smbmap-share-permissions.txt):

```

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[\] Checking for open ports...                                                                                                    


[*] Detected 1 hosts serving SMB
[|] Authenticating...                                                                                                    


[*] Established 1 SMB connections(s) and 0 authenticated session(s)
[!] Something weird happened on (10.211.55.2) Error while reading from remote on line 1015
[/] Closing connections..                                                                                                    


[-] Closing connections..                                                                                                    


[\] Closing connections..                                                                                                    


[|] Closing connections..                                                                                                    


[/] Closing connections..                                                                                                    


[-] Closing connections..                                                                                                    


                                                                                                    


[*] Closed 1 connections


```
```bash
smbmap -u null -p "" -H 10.211.55.2 -P 445 2>&1
```

[/home/lizi/Desktop/myproj/PenRecon/web-backend/results/10.211.55.2/scans/tcp445/smbmap-share-permissions.txt](file:///home/lizi/Desktop/myproj/PenRecon/web-backend/results/10.211.55.2/scans/tcp445/smbmap-share-permissions.txt):

```

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[\] Checking for open ports...                                                                                                    


[*] Detected 1 hosts serving SMB
[|] Authenticating...                                                                                                    


[*] Established 1 SMB connections(s) and 0 authenticated session(s)
[!] Something weird happened on (10.211.55.2) Error while reading from remote on line 1015
[/] Closing connections..                                                                                                    


[-] Closing connections..                                                                                                    


[\] Closing connections..                                                                                                    


[|] Closing connections..                                                                                                    


[/] Closing connections..                                                                                                    


[-] Closing connections..                                                                                                    


                                                                                                    


[*] Closed 1 connections


```
```bash
smbmap -H 10.211.55.2 -P 445 -r 2>&1
```

[/home/lizi/Desktop/myproj/PenRecon/web-backend/results/10.211.55.2/scans/tcp445/smbmap-list-contents.txt](file:///home/lizi/Desktop/myproj/PenRecon/web-backend/results/10.211.55.2/scans/tcp445/smbmap-list-contents.txt):

```

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[\] Checking for open ports...                                                                                                    


[*] Detected 1 hosts serving SMB
[|] Authenticating...                                                                                                    


[*] Established 1 SMB connections(s) and 0 authenticated session(s)
[!] Something weird happened on (10.211.55.2) Error while reading from remote on line 1015
[/] Closing connections..                                                                                                    


[-] Closing connections..                                                                                                    


[\] Closing connections..                                                                                                    


[|] Closing connections..                                                                                                    


[/] Closing connections..                                                                                                    


[-] Closing connections..                                                                                                    


                                                                                                    


[*] Closed 1 connections


```
```bash
smbmap -u null -p "" -H 10.211.55.2 -P 445 -r 2>&1
```

[/home/lizi/Desktop/myproj/PenRecon/web-backend/results/10.211.55.2/scans/tcp445/smbmap-list-contents.txt](file:///home/lizi/Desktop/myproj/PenRecon/web-backend/results/10.211.55.2/scans/tcp445/smbmap-list-contents.txt):

```

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[\] Checking for open ports...                                                                                                    


[*] Detected 1 hosts serving SMB
[|] Authenticating...                                                                                                    


[*] Established 1 SMB connections(s) and 0 authenticated session(s)
[!] Something weird happened on (10.211.55.2) Error while reading from remote on line 1015
[/] Closing connections..                                                                                                    


[-] Closing connections..                                                                                                    


[\] Closing connections..                                                                                                    


[|] Closing connections..                                                                                                    


[/] Closing connections..                                                                                                    


[-] Closing connections..                                                                                                    


                                                                                                    


[*] Closed 1 connections


```
```bash
smbmap -H 10.211.55.2 -P 445 -x "ipconfig /all" 2>&1
```

[/home/lizi/Desktop/myproj/PenRecon/web-backend/results/10.211.55.2/scans/tcp445/smbmap-execute-command.txt](file:///home/lizi/Desktop/myproj/PenRecon/web-backend/results/10.211.55.2/scans/tcp445/smbmap-execute-command.txt):

```

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[\] Checking for open ports...                                                                                                    


[*] Detected 1 hosts serving SMB
[|] Authenticating...                                                                                                    


[*] Established 1 SMB connections(s) and 0 authenticated session(s)
[/] Closing connections..                                                                                                    


[-] Closing connections..                                                                                                    


[\] Closing connections..                                                                                                    


[|] Closing connections..                                                                                                    


[/] Closing connections..                                                                                                    


[-] Closing connections..                                                                                                    


                                                                                                    


[*] Closed 1 connections


```
```bash
smbmap -u null -p "" -H 10.211.55.2 -P 445 -x "ipconfig /all" 2>&1
```

[/home/lizi/Desktop/myproj/PenRecon/web-backend/results/10.211.55.2/scans/tcp445/smbmap-execute-command.txt](file:///home/lizi/Desktop/myproj/PenRecon/web-backend/results/10.211.55.2/scans/tcp445/smbmap-execute-command.txt):

```

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[\] Checking for open ports...                                                                                                    


[*] Detected 1 hosts serving SMB
[|] Authenticating...                                                                                                    


[*] Established 1 SMB connections(s) and 0 authenticated session(s)
[/] Closing connections..                                                                                                    


[-] Closing connections..                                                                                                    


[\] Closing connections..                                                                                                    


[|] Closing connections..                                                                                                    


[/] Closing connections..                                                                                                    


[-] Closing connections..                                                                                                    


                                                                                                    


[*] Closed 1 connections


```
