<p align="center">
  <a href="https://junedns.com"><img src="logo.png" title="JuNeDNS Server" width="570" height="300" /></a>
</p>
<h1 align="center">
  <a href="https://github.com/EduardoRuizM/junedns-server">EduardoRuizM/junedns-server</a>
</h1>
<p align="center">
  Dataclick Olimpo <a href="https://junedns.com">☀️JuNeDNS Server</a>
  Safe, Lightweight and Full DNS Server ideal for single or hosting servers
  https://www.junedns.com
</p>

# [☀️JuNeDNS Server](https://junedns.com "JuNeDNS Server")
## 🌐 Full DNS Server for single or hosting multi-domains

JuNeDNS Server is a lightweight DNS authoritative and recursive server created in Node.js with a fully functionality and easy installation and use.
![10 Kb](https://img.shields.io/github/size/EduardoRuizM/junedns-server/server.js)

- Use a **MySQL/MariaDB** database to store information about your domains and records.
- UDP/TCP compatible (port 53), DNS-over-TLS (DoT) and DNS-over-HTTPS (DoH).
- SOA, A, AAAA, MX, TXT, SRV, NS, CNAME, PTR, SPF, CAA, NAPTR, TLSA, RRSIG, DS and DNSKEY records.
- Let´s Encrypt API to create/renew SSL certificates.
- Auto restart DoT/DoH on certificates renew.
- Dynamic IP to a static host (No-IP).
- Maybe used as general DNS server forwarding resolve requests if domain is not hosted.
- Binaries compiled (x64 bits) for: 🐧Linux, 🪟 Windows and 🍎MacOS.
- DNSSEC, DKIM, DMARC and service running in IPv4/IPv6 in [PRO version](https://junedns.com "PRO version").
- Use [JuNeDNS Backend](https://github.com/EduardoRuizM/junedns-backend "JuNeDNS Backend") & [JuNeDNS Frontend](https://github.com/EduardoRuizM/junedns-frontend "JuNeDNS Frontend") & [JuNeDNS No-IP](https://github.com/EduardoRuizM/junedns-noip "JuNeDNS No-IP") for a whole DNS solution.

### Why JuNeDNS Server?
✔ All DNS server features that a DNS server requires.
✔ Safe, lightweight, and easy installation.
✔ Detailed information about JuNeDNS functionallity.
✔ All about domains DNS service/protocol knowledge you need are here in this documentation.
✔ Support for IDN (internationalized domain name) for non-ASCII characters (coding in Punycode).
✔ You don´t need anything else in a DNS server system (protocols/records that really unused, bloatware).
✔ So, perfect for advanced or beginners SysAdmins.
✔ Just insert domains and records into database without restart DNS service.
✔ Forget about complicated text config files for DNS zones.
✔ Control Your DNS directly in Your server.
✔ Do not depend on external DNS like Cloudflare that can be attacked and disabled, or with security issues like *Authenticated Origin Pulls*, causing your domains not to resolve for a while - [Downdetector](https://downdetector.com/status/cloudflare/ "Downdetector").

# Author
[Eduardo Ruiz](https://github.com/EduardoRuizM) <<eruiz@dataclick.es>>

# [JuNe](https://just-needed.com "JuNe") / JUst NEeded Philosophy
1. **Source code using less code as possible**
  So you can understand code and find bugs easier.
2. **Few and optimized lines is better**
  Elegant design.
3. **Avoid external dependences abuse/bloated, and possible third-party bugs**
  Less files size, better and faster to the interpreter.
4. **Clear and useful documentation with examples and without verbose**
  Get to the point.
5. **Avoid showing unsolicited popups, notifications or messages in frontend**
  For better User eXperience.
6. **Simple UI**, without many menus/options and with few clicks to get to sites.
7. Consequences of having a lot of code (and for simple things): Having to work and search through many files and folders with a lot of wasted time, successive errors due to missing unknown files, madness to move a code to another project, errors due to recursive dependencies difficult to locate, complexity or impossibility to migrate to new versions, unfeasibility to follow the trace with so much code, risk of new errors if the functionality is extended, problems not seen at the first sight, general slowness in the whole development due to excessive and unnecessary code.

Have a look to [JuNe BackServer](https://github.com/EduardoRuizM/june-backserver "JuNe BackServer") in Backend.

# Installation
### 1. Create MySQL/MariaDB database
```
CREATE DATABASE IF NOT EXISTS junedns;
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP ON junedns.* TO 'junednsusr'@'localhost' IDENTIFIED BY 'YOUR_PASSWORD_HERE';
FLUSH PRIVILEGES;
USE junedns;
```
- With only ´localhost´ instead ´%´ we ensure access only from the same computer.

👉 And create tables using **[mysql.sql](./mysql.sql "mysql.sql")**

### 2. Create config file
File **junedns.conf**
```
// Protocols
protocol_ipv4=true
protocol_ipv6=true
protocol_dot=false
protocol_doh=false

// Database
mysql_host=127.0.0.1
mysql_port=3306
mysql_name=junedns
mysql_user=junednsusr
mysql_pass=

// Verbose logs in JuNeDNS_PATH/junedns.log
// 0=None, 1=Errors, 2=All (3=debug)
log=0

// Main domain for PTR, and DNSSEC (PRO version)
main_domain=mydomain.tld

// Server public IP address for PTR and backend
ipv4=1.2.3.4
ipv6=

// DNS-over-TLS (DoT)
dot_cert=
dot_key=

// DNS-over-HTTPS (DoH)
doh_port=8085
doh_cert=
doh_key=

// Forward resolve requests if domain is not hosted
forward=false
forward_pri_ipv4=8.8.8.8
forward_sec_ipv4=8.8.4.4
forward_pri_ipv6=
forward_sec_ipv6=

// -- Only PRO version --
license_key=
license_name=
dnssec=true
dkim_path=
dkim_genkey=
dkim_selector=

// For backend
backend_url=http://localhost:9053
backend_cert=
backend_key=
backend_api=false
```
Changes requires restart JuNeDNS Server / You need root privileges for installation.

- **🐧Linux:** For security reasons limit file access with `chmod 600 junedns.conf`

Important variables to be setted are **mysql_** and **ipv4 / ipv6**

<i class="fa-solid fa-triangle-exclamation"></i> BEWARE! Setting **forward=true** your server maybe attacked using open DNS resolver vulnerability.

**forward_pri_ipv4 / forward_sec_ipv4** public primary and secondary DNS server addresses to resolve external domains, in Linux you can use same as */etc/resolv.conf*, (not very necessary to use forward IPv6):

| DNS server: | Primary IPv4 | Secondary IPv4 | Primary IPv6 | Secondary IPv6 |
| --- | :---: | :---: | :---: | :---: |
| **Google** | 8.8.8.8 | 8.8.4.4 | 2001:4860:4860::8888 | 2001:4860:4860::8844 |
| **Quad9** | 9.9.9.9 | 149.112.112.112 | 2620:fe::fe | 2620:fe::9 |
| **OpenDNS** | 208.67.222.222 | 208.67.220.220 | 2620:0:ccc::2 | 2620:0:ccd::2 |
| **Cloudflare** | 1.1.1.1 | 1.0.0.1 | 2606:4700:4700::1111 | 2606:4700:4700::1001 |
| **Alternate DNS** | 76.76.19.19 | 8.20.247.20 |  2602:fcbc::ad | 2602:fcbc:2::ad |

Or have a look to https://public-dns.info

### 3 Running
Run JuNeDNS Server using Node.js with source code or from binary:

#### 3.1 Running from Node.js with source code
Download or clone this repository.
Install dependencies `npm install` (JuNe 1 dependence: MySQL).

**Requirements** [node.js](https://nodejs.org) and [Node Package Manager](https://www.npmjs.org) (NPM).

- **Running from command line** (for example to debug)
-`node server.js` or `npm start`

- **Running as service**

  - **🐧Linux:**
	- Create or copy config file **junedns.conf** in the same folder and chmod 600.
	- Create or copy Systemctl service `junedns.service` in folder `/etc/systemd/system` or `/usr/lib/systemd/system` use ExecStart Source code execution line and adjust path if necessary.
	- Enable and start service `systemctl enable junedns.service && systemctl start junedns.service` check if running `systemctl status junedns.service`

  - **🪟 Windows:**
    - Create or copy config file **junedns.conf** in the same folder and set correctly PATHs.
    - Create service `sc create "JuNeDNS Server" binPath="NodeJS_PATH\node JuNeDNS_PATH\server.js"` start with `net start "JuNeDNS Server"`

#### 3.2 Running from binaries (x64 bits)
Download and decompress your version: [🐧Linux](https://junedns.com/file/junedns-server-linux.zip "Linux") (20 Mb), [🪟 Windows](https://junedns.com/file/junedns-server-win.zip "Windows") (16 Mb) or [🍎MacOS](https://junedns.com/file/junedns-server-macos.zip "MacOS") (20 Mb).
Create [junedns.conf](./junedns.conf "junedns.conf")

- **Running from command line** (for example to debug with **log=3**)
-`./junedns` or `junedns`

- **Running as service**

  - **🐧Linux:**
    - Create a folder such as /etc/junedns `mkdir /etc/junedns` and copy file in it.
    - Add executable permission `chmod +x /etc/junedns/junedns`
	- Create or copy config file **junedns.conf** in the same folder `/etc/junedns/junedns.conf` and chmod 600.
	- Create or copy Systemctl service `junedns.service` in folder `/etc/systemd/system` or `/usr/lib/systemd/system` use ExecStart Binary execution line and adjust path if necessary.
	- Enable and start service `systemctl enable junedns.service && systemctl start junedns.service` check if running `systemctl status junedns.service`

  - **🪟 Windows:**
    - Create a folder with permissions such as `C:\Users\[USER]\AppData\Roaming\JuNeDNS` and copy file in it.
    - Create or copy config file **junedns.conf** in the same folder `C:\Users\[USER]\AppData\Roaming\JuNeDNS\junedns.conf`
    - Create service `sc create "JuNeDNS Server" binPath="C:\Users\[USER]\AppData\Roaming\JuNeDNS\junedns.exe"` start with `net start "JuNeDNS Server"`

**🐧Linux:** Uncomment the ExecStart line you need for `junedns.service`
```
[Unit]
Description=JuNeDNS Server
After=network.target

[Service]
Type=simple
# Select only 1 ExecStart
#ExecStart=/etc/junedns/junedns							#Binary execution
#ExecStart=/usr/bin/node /etc/junedns/server.js	#Source code execution
Restart=always
TimeoutStartSec=0

[Install]
WantedBy=default.target
```

### 4. Insert domains and records
- Do not end records names with a dot, or use @ such as bind/named
- JuNeDNS considers Root Zone the Second-level domain (SLD or 2LD).
- Domain/Records names must be Punycode if name contains special characters, such as accents.
Punycode encoding converter: https://www.punycoder.com (not necessary if using backend).
- MX (Mail eXchange) records must point to an A/AAAA record with an IP, not to a CNAME because some providers consider this as spam senders.
- Using IPv6 gives a touch of quality, configure your server that way or request an IPv6 address to your hosting provider. Then you must repeat each A record with it´s equivalent AAAA IPv6 address.
- If IP server is: **1.2.3.4**, then reversed PTR record is **4.3.2.1.in-addr.arpa**
  IPv6 performed in the same reversing way ending with **ip6.arpa**
- For the following example:
  - **nsdomain.tld** Main domain where NS point to.
  - **info@nsdomain.tld** Main domain Email address (@ changed by dot).

```
INSERT INTO domains SET id=1, name='mydomain.tld';

INSERT INTO records SET domain_id=1, name='mydomain.tld', type='SOA', content='ns1.nsdomain.tld info.nsdomain.tld 3 10380 3600 604800 3600';
INSERT INTO records SET domain_id=1, name='mydomain.tld', type='A', content='1.2.3.4';
INSERT INTO records SET domain_id=1, name='mydomain.tld', type='AAAA', content='i:want:an:ipv6:address:so:change:me';
INSERT INTO records SET domain_id=1, name='mydomain.tld', type='NS', content='ns1.nsdomain.tld';
INSERT INTO records SET domain_id=1, name='mydomain.tld', type='NS', content='ns2.nsdomain.tld';
INSERT INTO records SET domain_id=1, name='www.mydomain.tld', type='CNAME', content='mydomain.tld';
INSERT INTO records SET domain_id=1, name='mydomain.tld', type='MX', content='mail.mydomain.tld 10';
INSERT INTO records SET domain_id=1, name='mail.mydomain.tld', type='A', content='1.2.3.4';
INSERT INTO records SET domain_id=1, name='mail.mydomain.tld', type='AAAA', content='i:want:an:ipv6:address:so:change:me';
INSERT INTO records SET domain_id=1, name='mydomain.tld', type='TXT', content='v=spf1 mx -all';
```

### PTR record
You should add a PTR record for the server **main_domain** reverse lookup specified in **junedns.conf** and containing *hostname* of the machine with the main domain.
```
INSERT INTO records SET domain_id=1, name='maindomain.tld', type='PTR', content='hostname.maindomain.tld';
```

### SPF (Sender Policy Framework)
Standard record that lists all authorized servers to send Emails in the domain to avoid spoofing attacks:
```
INSERT INTO records SET domain_id=1, name='mydomain.tld', type='TXT', content='v=spf1 mx -all';
```
| -all | Fails authentication |
| --- | --- |
| ~all | Softfails authentication |
| +all | Passes authentication |
| ?all | Neutral |

| Service | SPF record |
| --- | --- |
| Google Workspace | `v=spf1 a mx include:_spf.google.com ~all` |
| Microsoft Exchange | `v=spf1 include:spf.protection.outlook.com -all` |
| Mailchimp | `v=spf1 include:spf.mandrillapp.com ?all` |

#### MX records for Google Workspace
```
INSERT INTO records SET domain_id=1, name='mydomain.tld', type='MX', content='aspmx.l.google.com 1';
INSERT INTO records SET domain_id=1, name='mydomain.tld', type='MX', content='alt1.aspmx.l.google.com 5';
INSERT INTO records SET domain_id=1, name='mydomain.tld', type='MX', content='alt2.aspmx.l.google.com 5';
INSERT INTO records SET domain_id=1, name='mydomain.tld', type='MX', content='alt3.aspmx.l.google.com 10';
INSERT INTO records SET domain_id=1, name='mydomain.tld', type='MX', content='alt4.aspmx.l.google.com 10';
```

### DKIM record sample
Available in [PRO version](https://junedns.com "PRO version"), automatically added.
```
INSERT INTO records SET domain_id=1, name='auth._domainkey.mydomain.tld', type='TXT', content='v=DKIM1; h=rsa-sha256; k=rsa; p=DKIM_KEY_HERE';
```

### DMARC record
```
INSERT INTO records SET domain_id=1, name='_dmarc.mydomain.tld', type='TXT', content='v=DMARC1; p=reject; pct=100';
```
p=Policy: reject, none (no action) or quarantine (move to junk/spam Email folder).

### 5. Test
- Make a test by performing a DNS lookup using local address where JuNeDNS Server is running (127.0.0.1):

| nslookup command | Function |
| --- | --- |
| `nslookup mydomain.tld 127.0.0.1` | General domain test A/AAAA |
| `nslookup -type=soa mydomain.tld 127.0.0.1` | For SOA record |
| `nslookup -debug -type=a mydomain.tld 127.0.0.1` | For A record and show detailed debug |

- Or use more complete [dig](https://www.isc.org/download "dig") installing for Linux or [Windows](https://downloads.isc.org/isc/bind9/9.16.38/BIND9.16.38.x64.zip "Windows"):

| dig command | Function |
| --- | --- |
| `dig @127.0.0.1 A mydomain.tld` | For A record |
| `dig @127.0.0.1 A +dnssec mydomain.tld` | Requesting A with DNSSEC |

- Also you can test DNS using online tools as:
  https://dnslookup.online
  https://toolbox.googleapps.com/apps/dig/
  https://www.whatsmydns.net/dns-lookup
  https://dnschecker.org/all-tools.php

## About Internet new protocols
Implementation of new Internet protocols is a hard way, because all systems have the original protocols first, and new ones are not usually adapted, and unable to replace them. We can see many examples such as IPv6, HTTP/2, HTTP/3 Quic, DNSSEC (neither Google or Microsoft use it), DoT or DoH...

The new protocols: DoT (DNS-over-TLS) and DoH (DNS-over-HTTPS) proposed at Internet Engineering Task Force (IETF) to encrypt DNS traffic, to prevent eavesdropping and manipulation of DNS data via man-in-the-middle attacks.
But since UDP is the main DNS protocol, it´s not recommended to disable it and enable only the new ones protocols for backwards reasons and to avoid to be unreachable, you must combine them. Therefore, using it is more exotic than functional.

# DNS-over-TLS (DoT)
Encrypts DNS traffic queries through the Transport Layer Security (TLS) protocol on port 853.
Set `protocol_dot=true`, `dot_key` and `dot_cert` (Let´s Encrypt) certificates paths in **junedns.conf**

# DNS-over-HTTPS (DoH)
Encrypts DNS traffic queries through a Hypertext Transfer Protocol Secure encrypted session (HTTPS) on port 443 and endpoint: */dns-query*
Set `protocol_doh=true`, `doh_key` and `doh_cert` (Let´s Encrypt) certificates paths in **junedns.conf**
Example:
```
doh_port=443
doh_cert=ACME_PATH/mydomain.tld/fullchain.cer
doh_key=ACME_PATH/mydomain.tld/mydomain.tld.key
```
If you have conflicts with port 443 (HTTPS) due to a Web server service running in the same machine like Nginx, then you can proxy DoH port from an available free **doh_port=8085** to 443, and empty values for **doh_cert / doh_key** to force JuNeDNS Server to run DoH in HTTP mode (so SSL certificate through Nginx):
```
doh_port=8085
doh_cert=
doh_key=
```
Nginx config:
```
server {
	listen		443 ssl;
	listen		[::]:443 ssl; #http3?
	server_name	mydomain.tld;

	ssl_certificate		ACME_PATH/mydomain.tld/fullchain.cer;
	ssl_certificate_key	ACME_PATH/mydomain.tld/mydomain.tld.key;
	ssl_protocols			TLSv1.2 TLSv1.3;

	location / {
		proxy_set_header	X-Forwarded-For $remote_addr;
		proxy_set_header	Host $http_host;
		proxy_pass		http://127.0.0.1:8085;
	}
}
```
With this technique you could combine your Website and DoH in the same server with location /dns-query
Test it (to output file): `curl -H "accept: application/dns-json" "http://127.0.0.1:8085/dns-query?name=mydomain.tld&type=A" --output file.bin`

# DNSSEC
Available in [PRO version](https://junedns.com "PRO version"), **dnssec=true** in `junedns.conf`
Domain Name System Security Extensions, provides cryptographic authentication of DNS records, according to [RFC 4035](https://www.ietf.org/rfc/rfc4035.txt "RFC 4035"), with Authenticated Data (AD) and Checking Disabled (CD) flags on header.
ZSK (Zone Signing Keys) and KSK (Key Signing Keys) private and public DNSSEC keys will be created and inserted into database automatically on the first resolve request.
DS, DNSKEY and RRSIGs records are dynamically generated by JuNeDNS Server, so they don´t appear in records database table.
- Show RRSIG record using `dig @127.0.0.1 A +dnssec mydomain.tld`
```
mydomain.tld.        3600    IN  A   1.2.3.4
mydomain.tld.        3600    IN  RRSIG   A 8 2 3600 20230715080515 20230615080515 50238 mydomain.tld. DAtckAl17....
```
- Show DNSKEYs records using `dig @127.0.0.1 DNSKEY +multi mydomain.tld`
- Show DS (Delegation Signer) records using `dig @127.0.0.1 DS mydomain.tld`

# DKIM
Available in [PRO version](https://junedns.com "PRO version").
Domain Keys Identified Mail, for Email authentication with digital signature to prevent spoofing, phishing and spam.
Install from [OpenDKIM](http://www.opendkim.org "OpenDKIM") and configure it.
DKIM signature and setup will be created and inserted into database automatically on the first resolve request, so it´s mandatory to config OpenDKIM path for domains, binary to GenKey, and DKIM selector (same as Selector in opendkim.conf):
```
dkim_path=/etc/opendkim
dkim_genkey=/usr/sbin/opendkim-genkey
dkim_selector=auth
```

# DMARC
Domain-based Message Authentication, Reporting and Conformance, protect Email from unauthorized use for Email spoofing, indicating that Emails are protected by SPF and/or DKIM.

# Logs
For security, maximum log size per file will be 50 Mb or truncate.

## Reading logs
Line formats in `junedns.log` when `log=2` (or 3) in `junedns.conf`
- REQ = Request, RES = Response, FWD = Forward to external DNS, ERR = Error, or NXDOMAIN.
  `yyyy-mm-dd hh:mm:ss [REQ|RES|FWD|ERR] IP: <ip> protocol info`
  protocol: UDP, TCP, DoT or DoH.
  Sample of mydomain.tld SOA resolve Request from IP 1.2.3.4 UDP (info = DNS request in JSON):
  `2023-06-15 09:45:05 [REQ] IP: <1.2.3.4> UDP {"header":{"id":2,"qr":1,"opcode":0,"aa":0,"tc":0,"rd":1,"ra":0,"z":0,"ad":0,"cd":0,"rcode":0,"qdcount":1,"nscount":0,"arcount":0,"ancount":0},"questions":[{"name":"mydomain.tld","type":6,"class":1}],"answers":[],"authorities":[],"additionals":[]}`
- Response returned by JuNeDNS Server (info = TYPE NAME -> generated JSON):
  `2023-06-15 09:45:05 [RES] IP: <1.2.3.4> UDP SOA mydomain.tld -> {"name":"mydomain.tld","type":6,"class":1,"ttl":259200,"primary":"ns1.nsdomain.tld","admin":"info.mydomain.tld","serial":"3","refresh":"10380","retry":"3600","expiration":"604800","minimum":"3600"}`
- Error sample if log is not 0 in `junedns.conf`
  `2023-06-15 09:45:05 [ERR] IP: <1.2.3.4> UDP ER_BAD_DB_ERROR: Unknown database 'junedns'`
- NXDOMAIN if log is not 0 and Non-eXistent Domain:
  `2023-06-15 09:45:05 [NXDOMAIN] IP: <1.2.3.4> UDP nonexistentdomain.tld`
  This is useful if you need to prevent NXDOMAIN Flood DDoS attacks, see [Fail2ban](#Fail2ban).

## Rotate logs
**🐧Linux:** Add rotate log functionality and keep in mind that log file will be increase over time.
- Your could change log file path to `/var/log/junedns.log` and changing *const flog* value in **server.js**
- Create file `/etc/logrotate.d/junedns` and set correctly JuNeDNS_PATH

```
JuNeDNS_PATH/junedns.log {
        daily
        missingok
        rotate 4
        compress
        copytruncate
        create 600 root root
}
```

# Compile JuNeDNS Server
Get executable compiled in folder **dist/** (x64 bits) for: 🐧Linux, 🪟 Windows and 🍎MacOS.
- Rename **package.json** to **package.bak.json**
- Then rename **package.compile.json** to **package.json** to use *Package your Node.js (pkg)*
- And run `npm run build` or by platform `npm run build-linux` (or build-win, build-macos)

# Let´s Encrypt
Using [acme.sh](https://github.com/acmesh-official/acme.sh "acme.sh") to create/renew SSL certificates for HTTPS, and create TXT domain challenge.
- Copy **dns_junedns.sh** to folder `ACME_PATH/dnsapi`
- Be sure MySQL/MariaDB **client** installed on server `sudo apt install mariadb-client`
- Add database parameters to `ACME_PATH/account.conf`

```
JUNEDNS_DBName='junedns'
JUNEDNS_DBUser='junednsusr'
JUNEDNS_DBPass=''
```
Then to create a new certificate:
`ACME_PATH/acme.sh --issue --dns dns_junedns -d "mydomain.tld" --server letsencrypt`

Let´s Encrypt is free but only 3 months validity.
Add cron task to automatically renew SSL certificates:
`ACME_PATH/acme.sh --home "ACME_PATH" --renew-all --stopRenewOnError --server letsencrypt --cron`
Use --server letsencrypt to allow * wildcard domains (default ZeroSSL not supported).

✔️JuNeDNS detects if certificates are renewed (different datetime) and restarts DoT or DoH automatically.

### Certificates
SSL certificates are always needed from a Certification Authority entity (CA), because software like browsers require a trusted signer (we don´t know why / what exactly these entities certifies about us❓), unless you want to see the scary browser warning about ´Potential Security Risk´.
If you want to generate a self-signed certificate key pair, only for testing/development purposes (not for production environments) private-key.pem and public-cert.pem:
```
openssl genrsa -out private-key.pem 2048
openssl req -new -key private-key.pem -out csr.pem
openssl x509 -req -in csr.pem -signkey private-key.pem -out public-cert.pem
```

# Security issues
🛡️Just in case you want to know how apply Fail2ban and Iptables.
Although no real way to protect yourself against these attacks.

## Fail2ban
If you want to prevent DDoS / brute force attacks you can use [Fail2ban](https://www.fail2ban.org "Fail2ban").
Don´t forget that you may receive several resolve requests from the same IP (others DNS servers), although of different users.
Set maxretry to a high value. Example for UDP:
- Set `log=2` in `junedns.conf`
- Create `/etc/fail2ban/jail.d/junedns.conf`
```
[junedns-iptables]
enabled = true
port = dns
filter = junednsfilter
action = iptables[name=junedns, port=53, protocol=udp]
logpath = /etc/junedns/junedns.log
maxretry = 10
```
- Create `/etc/fail2ban/filter.d/junednsfilter.conf`
```
[Definition]
failregex = ^.+IP: <HOST>.+$
ignoreregex =
```
- Filter to prevent NXDOMAIN Flood DDoS attacks:
```
[Definition]
failregex = ^.+NXDOMAIN.+IP: <HOST>.+$
ignoreregex =
```
- Unban IP `fail2ban-client set junedns-iptables unbanip 1.2.3.4`

## Iptables
To protect against DDoS (Distributed Denial of Service) attacks or DNS amplification DDoS attacks, you could limit rate to accept queries.
```
iptables -A INPUT -p udp –dport 53 -m hashlimit
–hashlimit-name DNS –hashlimit-above 20/second –hashlimit-mode srcip
–hashlimit-burst 100 –hashlimit-srcmask 28 -j DROP
```

# JuNeDNS Backend & Frontend & No-IP
https://github.com/EduardoRuizM/junedns-backend
https://github.com/EduardoRuizM/junedns-frontend
https://github.com/EduardoRuizM/junedns-noip

# Trademarks©️
**Dataclick Olimpo JuNeDNS**
- [Dataclick.es](https://www.dataclick.es "Dataclick.es") is a software development company since 2016.
- [Olimpo](https://www.dataclick.es/en/technology-behind-olimpo.html "Olimpo") is a whole solution software to manage all domains services such as hosting services and to create Webs in a server.
- [JuNe](https://just-needed.com "JuNe") / JUst NEeded Philosophy, available software and development solutions.
- [JuNeDNS](https://junedns.com "JuNeDNS") is a part of Dataclick Olimpo domains management for DNS service, released to Internet community.
- Feel free to use JuNeDNS acording MIT license respecting the brand and image logotype that you can use.

# Import from PowerDNS
Using SQL sentences to export domains / records, and with access to both databases (adjust names).
Truncate JuNeDNS tables to start from scratch:
```
DELETE FROM junedns.domains;
INSERT INTO junedns.domains (id, name, nopunycode, created)
SELECT id, name, name, CURRENT_DATE FROM powerdns.domains;

DELETE FROM junedns.records;
INSERT INTO junedns.records (domain_id, name, type, content, ttl, disabled)
SELECT domain_id, name, type, TRIM(CONCAT_WS('', content, ' ', prio)), ttl, disabled FROM powerdns.records;
```

# Files
| File | Description |
| --- | --- |
| lib/ | Dependences classes and constants |
| dns_junedns.sh | Let´s Encrypt API for acme.sh to create/renew SSL certificates |
| junedns.conf | Configuration file for database, etc... |
| junedns.service | Systemctl service for binary or source code execution |
| logo.png | JuNeDNS Logo free to use |
| mysql.sql | MySQL/MariaDB database tables |
| package.compile.json | package.json file to compile binaries in folder **dist/** |
| package.json | Original package.json |
| README.md | Full guide about JuNeDNS and DNS service/protocol in markdown |
| server.js | Lightweighted JuNeDNS Server main file, just **20 Kb** (JuNe Philosophy) |

# Comparison
|   | JuNeDNS | PowerDNS | Diff % |
| --- | ---: | ---: | ---: |
| **Source Code** | 63 Kb | 7.503 Kb | 0,8 % |
| **Files / Folders** | 5 / 1 | 663 / 35 | 0,7 % / 2,8 %  |
| **Compiled** | 50 Mb | 394 Mb | 13 % |
| **Memory pmap** | 50 Mb | 1.406.492 Kb | 13 % |
