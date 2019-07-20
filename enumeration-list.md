**My Enumeration List**

	## Nmap 
		- Generic
			- nmap -A ipaddress
			- nmap -Pn -sT -T5 -sV 10.11.1.13
			- nmap -Pn -sU -sV 10.11.1.13
			- #shorter # nmap -sU --top-ports 200 -sV -Pn 10.11.1.71
			- # nmap -Pn -sT -sU -sV 10.11.1.13 - takes forever
			- unicornscan -mT 10.10.10.117
			- unicornscan -mU 10.10.10.117
		○ Generic script
			§ nmap -Pn -pPortsdiscovered --script=vuln,exploit 10.11.1.227
		○ onetwopunch
			§ ./onetwopunch.sh -t target.txt -p all -i tap0 -n -sV
			§ https://github.com/superkojiman/onetwopunch
		
	
	##HTTP:
    - Note: Whenever you get any credentials, use them for every user and every access you know of
		○ Browse manually
			§ robots.txt
			§ Index.html/asp/php/apsx
			§ View-source : Search for passwords!
			§ curl http://10.11.1.71 -s -L | html2text -width '99' | uniq
			§ login.html/...
			§ Version information - view source or search for license/readme(dirbust)
		○ Check for upload functionality!!!!
			§ Upload payloads are in /ftphome
		○ whatweb -v http://10.11.1.227:80
			§ whatweb -a 3 http://10.11.1.230
		○ nikto -host 10.11.1.227
			§ Nikto -C all ipaddress  --- too long
		○ Admin Screens
			§ Try Default username:password from Web
			§ Or usual combinations
				□ admin \ "" (blank), admin \ admin, admin \ password
				□ root \ "" (blank), root \ root, root \ password
				□ guest:guest
				□ Find possible usernames from blog posts or somewhere from the website
		○ nmap -sV -Pn -vv -p80 --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt
		○ For CVE-2017-12615, curl -X PUT "http://10.10.10.95:8080/" --upload-file webshell
		○ WebDav Enabled
			§ nmap -p80 --script=http-iis-webdav-vuln.nse 10.11.1.227
			§ davtest -url http://10.11.1.227/
				□ davtest -move -url http://10.11.1.14/
			§ cadaver 10.11.1.13
		○ Brute Force
			§ dirb http://10.11.1.227/
			§ dirb http://10.11.1.49 /usr/share/dirb/wordlists/vulns/iis.txt
			§ dirb http://10.11.1.49 /usr/share/dirb/wordlists/vulns/iis.txt
			§ gobuster -u http://10.11.1.71/ -w /usr/share/seclists/Discovery/Web_Content/common.txt -s '200,204,301,302,307,403,500' -e
			§ gobuster -u http://10.11.1.10/ -w /usr/share/seclists/Discovery/Web_Content/iis.txt -s '200,204,301,302,307,403,500' -e
			§ gobuster -u http://10.11.1.71/ -w /usr/share/seclists/Discovery/Web_Content/cgis.txt -s '200,204,301,302,307,403,500' -e
			§ gobuster -u http://10.11.1.10/ -w /usr/share/seclists/Discovery/Web_Content/CMS/ColdFusion.fuzz.txt -s '200,204,301,302,307,403,500' -e
			§ gobuster -u http://10.10.10.105/ -w /usr/share/dirb/wordlists/common.txt -s '200,204,301,302,307,403,500' -e
			
			§ Try with other Wordlists too! Based on the technology used! ---Don't really need this since the answer is much simpler
			§ Wordlists 
				§ DirB - /usr/share/dirb/wordlists/
				§ wfuzz - /usr/share/wfuzz/wordlist/
				§ SecList - /usr/share/seclists/
			§ Gobuster limitation is that it does not go beyond level one brute forcing
	
	## SSH
		○ Banner and Key fingrprint grabbing
			§ nmap -sT -Pn -p22 -sV --script=ssh-hostkey.nse 10.11.1.71
			§ ssh -v root@10.11.1.71
		§ SSH is known being 'stable' service - (which we know from researching CVEs).
		§ Privesc - Add a new key to /home/<user>/.ssh/authorizedkeys and ssh as the user
	
	## FTP
		○ Authenticate Using anonymous login!
			§ Web browse the entire directory structure
			§ Try put, send and get 
		○ nmap -sT --script=ftp* -p21,20 10.11.1.227
			§ nmap --script=ftp-anon.nse,ftp-bounce.nse,ftp-libopie.nse,ftp-proftpd-backdoor.nse,ftp-syst.nse,ftp-vsftpd-backdoor.nse,ftp-vuln-cve2010-4221.nse,tftp-enum.nse -p21,20 10.11.1.227
		○ Use PASV mode in FTP when transferring files
	
	## SMB
		○ enum4linux -a 10.11.1.8
		○ rpcclient -U "" 10.11.1.227  --- Null Logon
		○ nmap -sT -sU --script=smb* -p445,137,138,139 10.11.1.227
			§ nmap -sT -sU --script=smb-enum-users.nse,smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-ls.nse,smb-os-discovery.nse,smb-mbenum.nse -p445,137,138,139 10.11.1.227
		○ Everything w/o brute
			§ nmap -sT -sU --script smb-brute.nse,smb-double-pulsar-backdoor.nse,smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-flood.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-protocols.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve-2017-7494.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse,smb-vuln-regsvc-dos.nse,smb2-capabilities.nse,smb2-security-mode.nse,smb2-time.nse,smb2-vuln-uptime.nse -p445,137,138,139 10.11.1.227
		○ Note: 138,137 - UDP, 137,139-TCP (netbios) and 445 -TCP 
	
	## SNMP 
		○ snmp-check -c public 10.11.1.227
		○ ./snmpcheck-1.9.rb -c public 10.11.1.227
		○ perl ../common/scripts/snmpcheck-1.8.pl -t 10.11.1.227 -c public
		○ Try other known community strings like private
	
	##SMTP
		○ nmap -sT -p21,25 --script=smtp* 10.11.1.227
			§ nmap -sT --script=smtp-brute.nse,smtp-commands.nse,smtp-enum-users.nse,smtp-ntlm-info.nse,smtp-open-relay.nse,smtp-strangeport.nse,smtp-vuln-cve2010-4344.nse,smtp-vuln-cve2011-1720.nse,smtp-vuln-cve2011-1764.nse -p21,25 10.11.1.227
	
	## POP3 
		○ If you can login then [Using TELNET!]
			§ USER user
			§ PASS password
			§ LIST
			§ RETR 1
		○ nmap -sT -p110,995 --script=pop3-capabilities,pop3-ntlm-info 192.168.37.67
		
	## SQL
		○ Search credentials in Web Application!!!
		○ Find credentials and try authenticating to it
			§ sqsh -D bankdb -U sa -P poiuytrewq -S 10.11.1.31
			§ mysql -u phpmyadmin -p zaq1xsw2cde3 -h 127.0.0.1 phpmyadmin
		○ nmap -sT mysql-enum.nse,mysql-info.nse -p3306 10.11.1.227
		○ See ralph
		○ Dig deeper in all Databases found!!
	
	## RPC
		○ nmap -sT -sU --script=msrpc-enum.nse,rpc-grind.nse,rpcap-info.nse,rpcinfo.nse,xmlrpc-methods.nse -p111 10.11.1.227
		
		MS DCE RPC 
			§ https://security.stackexchange.com/questions/93542/enumeration-and-ms-dcerpc/96369
			§ Metasploit modules - endpoint_mapper, management, tcp_dcerpc_auditor
		
		Unix RPC
			§ http://etutorials.org/Networking/network+security+assessment/Chapter+12.+Assessing+Unix+RPC+Services/12.1+Enumerating+Unix+RPC+Services/
			§ rpcinfo -p 192.168.0.50  - query portmapper
			§ nmap -sR 10.0.0.9 --- redundant now
	
	## JAVA RMI
		○ nmap -sS -p1100,49157,49200 -sV --script=rmi-dumpregistry 10.11.1.73
		○ nmap -sS -p1100,49157,49200 -sV --script=rmi-vuln-classloader 10.11.1.73
	
	## DNS 
		○ dnsrecon -d thinc.local -t zonewalk
		○ dnsrecon -d megacorpone.com -t axfr


**Search exploits**
	• FIRST - Find version information 
	• Use searchsploit
	• Use metasploit
	• Google!!

**Finding exploit code**
	• http://www.exploit-db.com
	• http://1337day.com
	• http://www.securiteam.com
	• http://www.securityfocus.com
	• http://www.exploitsearch.net
	• http://metasploit.com/modules/
	• http://securityreason.com
	• http://seclists.org/fulldisclosure/
	• http://www.google.com


**Finding more information regarding the exploit**
	• http://www.cvedetails.com
	• http://packetstormsecurity.org/files/cve/[CVE]
	• http://cve.mitre.org/cgi-bin/cvename.cgi?name=[CVE]
	• http://www.vulnview.com/cve-details.php?cvename=[CVE]


**(Quick) "Common" exploits**
	- Warning. Pre-compiled binaries files. Use at your own risk.
	• http://web.archive.org/web/20111118031158/http://tarantula.by.ru/localroot/
	• http://www.kecepatan.66ghz.com/file/local-root-exploit-priv9/
	
	
**Reference enumeration lists**
	- http://www.0daysecurity.com/penetration-testing/enumeration.html

