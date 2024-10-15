[[Active Directory]] is used for Identity and Access Management, due to this it is a prime target for us. Before we can [[Exploiting Active Directory |exploit]] AD misconfigurations for privilege escalation, [[Lateral Movement and Pivoting |lateral movement]], and goal execution, we first need to gain access. We need to acquire an initial set of valid AD credentials. Due to the number of AD services and features, the attack surface for gaining an initial set of AD credentials is usually significant.
There are many ways to get breach into an AD environment, we could use a [[GoPhish|phishing]] campaign, use credentials find through [[Reconnaissance|OSINT]], or use one of the following methods, between many others.

# NTLM Authenticated Services
New Technology LAN Manager (NTLM) is the suite of security protocols used to authenticate users' identities in AD. NTLM can be used for authentication by using a challenge-response-based scheme called NetNTLM. This authentication mechanism is heavily used by the services on a network. However, services that use NetNTLM can also be exposed to the internet. Some examples are:
- Internally-hosted Exchange (Mail) servers that expose an Outlook Web App (OWA) login portal.
- Remote Desktop Protocol (RDP) service of a server being exposed to the internet.
- Exposed VPN endpoints that were integrated with AD.
- Web applications that are internet-facing and make use of NetNTLM.
NetNTLM, also often referred to as Windows Authentication or just NTLM Authentication, allows the application to play the role of a middle man between the client an AD. All authentication material is forwarded to a DC in the form of a challenge, and if completed successfully, the application will authenticate the user.
This means that the application is authenticating on behalf of the user and not authenticating the user directly on the application itself. This prevents the application from storing AD credentials, which should only be stored on a DC.
![[Pasted image 20241010190502.png]]
## Brute-force Login Attacks
These exposed services provide an excellent location to test credentials discovered using other means. However, these services can also be used directly in an attempt to recover an initial set of valid AD credentials. We could perhaps try to use these for brute force attacks if we recovered information such as valid email addresses during our initial [[Red Recon|recon]].
Since most AD environments have account lockout configured, we won't be able to run a full brute-force attack. Instead, we need to perform a password spraying attack. So instead of trying multiple different passwords, for a single username, we instead choose a single password and use it for multiple usernames. 
Now this of course is not a 10/10 method, as it will not only generate a lot of failed attempts that could be easily noticed but it may also not work as it is way harder to luck into a single password for multiple users than to get password from a single user. But still if our recon leads with information showing that this may be possible (by having something like an initial password) it is worth to know.
For this we could use [[Hydra]] for example:
```sh
hydra -L usernames.txt -p Changeme123 http-get://server.with.ntlmauth.com/:A=NTLM:F=401
```

# LDAP Bind Credentials
Another method of AD authentication that applications can use is Lightweight Directory Access Protocol (LDAP) authentication. LDAP authentication is similar to NTLM authentication. However, with LDAP authentication, the application directly verifies the user's credentials. The application has a pair of AD credentials that it can use first to query LDAP and then verify the AD user's credentials.
LDAP authentication is a popular mechanism with thir-party (non-Microsoft) applications that integrate with AD. These include apps and systems such as:
- Gitlab
- Jenkins
- Custom-developed web apps
- Printers
- VPNs
If any of these applications or services are exposed on the internet, the same type of attacks as those leveraged against NTLM can be used. However, since a service using LDAP authentication requires a set of AD credentials, it opens up additional attacks vectors. In essence, we can attempt to recover the AD credentials used by the service to gain authenticated access to AD.
![[Pasted image 20241010203655.png]]
If we could gain a foothold on the correct host, such as a Gitlab server, it might be as simple as reading the configuration files to recover these AD credentials. These often are stored in plain text in configuration files since the security model relies on keeping the location and storage configuration file secure rather than its contents. 
## LDAP Pass-back Attacks
This is a common attack against network devices, such as printers, when we have gained initial access to the internal network, such as plugging in a rogue device in a boardroom.
LDAP Pass-back attack can be performed when we gain access to a device's configuration where the LDAP parameters are specified. This can be, for example, the web interface of a network printer. Usually, credentials for these type of interfaces are kept to the default ones, such as `admin:admin`. But when they are not, we can alter the LDAP configuration, such as the IP or hostname of the LDAP server. In an LDAP Pass-back attack, we can modify this IP to our IP and then test the LDAP configuration, which will force the device to attempt LDAP authentication to our rouge device. From there we can intercept this authentication attempt to recover the LDAP credentials.

---

One example could be that we find a printer inside a network with the following address `printer.za.enterprise.com` , we could first try to check any existing directories with something like [[GoBuster]] 
```
gobuster dir -w common.txt -u http://printer.za.enterprise.com/ -t 64 
```
Here we find a directory `/settings` in which manages the printer LDAP settings. With the following interface
![[Pasted image 20241010232617.png]]
We can figure out the username pretty easily, but sadly even by inspecting the page the password is not there. If we try to intercept it with burp the same keeps true, and we cannot get the password. But, seeing as this probably makes an authentication request to the DC to test the LDAP credentials we could create a listener to intercept those credentials. 
We can create a quick listener with [[Netcat]] on port `389` as that is the default one for LDAP. And then change the server to our IP.
Now by doing this we get a connection back, but also receive this message.
![[Pasted image 20241010233443.png]]
`supportedCapabilities` indicates that we have a problem. Before the printer sends over the credentials, it is trying to negotiate the LDAP authentication method details. It will use this negotiation to select the most secure authentication method that both the printer and the LDAP server support. If the method is too secure, the credentials will not be transmitted in cleartext. With some methods, credentials won't be transmitted over the network at all, so we can't just use netcat to harvest those juicy credentials. We need to create a Rouge LDAP server and make it insecure enough to ensure that the credentials are sent in plaintext.
## Hosting a Rouge LDAP server
There are several ways to host a rogue server, we will use OpenLDAP for this one. By first installing and enabling `slapd`
```sh
sudo apt-get -y install slapd ldap-utils && sudo systemctl enable slapd
```
We can start by configuring the LDAP server using the following
```sh
sudo dpkg-reconfigure -p low slapd
```
We say, that we don't want an initial config or database. For our domain name we will use the `za.enterprise.com` part, or whatever the domain of our engagement is, and use the same for organization. Use MDB as our database, don't remove when purged and yes move old database.
Now we have our LDAP server, but first we need to dumb it down. We want to ensure that our LDAP server only supports **PLAIN** and **LOGIN** authentication methods. To do this we need to create a new ldif file, called `olcSaslSecProps.ldif` with the following content
```olcSaslSecProps.ldif
#olcSaslSecProps.ldif
dn: cn=config
replace: olcSaslSecProps
olcSaslSecProps: noanonymous,minssf=0,passcred
```
This file does the following. Specifies the SASL security properties (`olcSaslSecProps`). Disables mechanisms that support anonymous login (`noanonymous`). And specifies the minimum acceptable security strength with 0, meaning no protection (`minssf=0`).
Now we can use the ldif file to patch our LDAP server using the following
```sh
sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart
```
And it is done, to test if our config was applied we can use
```sh
ldapsearch -H ldap:// -x -LLL -s base -b "" supportedSASLMechanisms
```

## Capturing LDAP Credentials
Now that our server is configured, we can open [[Wireshark]], make it listen on our interface and look for any packet using the LDAP protocol, one of those should contain the password in plain text.
![[Pasted image 20241010235959.png]]

# Authentication Relays
Continuing with attacks that can be staged from our rogue device, we will check attacks against broader network authentication protocols. In Windows network, there are a significant amount of services talking to each other, allowing users to make use of the services provided by the network.
These services have to use built-in authentication methods to verify the identity of incoming connections. We will look how authentication looks from the network's perspective. Focusing on how NetNTLM is used by [[Network Services Vulnerabilities#SMB|SMB]].
## SMB
In networks that use Microsoft AD, AMB governs everything from inter-network file-sharing to remote administration. Even the fucking "Out of magenta" alert that our computer receives when we try to print in black and white.
However, the security of earlier versions of the SMB protocol was deemed insufficient. With several vulnerabilities and exploits, we could've recover credentials or even gain RCE on devices. Although some of these vulnerabilities were resolved in newer versions, some organizations just  do not update. Two of these exploits for NetNTLM are:
- Since the NTLM challenges can be intercepted, we can use offline cracking techniques to recover the password associated with the NTLM challenge. However, this cracking process is significantly slower than cracking NTLM hashes directly
- We can use our rogue device to stage a MITM attack, relaying the SMB authentication between the client and server, which will provide us with an active authenticated session and access to the target server.

## LLMNR, NBT-NS, and WPAD
We will use **Responder** to attempt to intercept the NetNTLM challenge to crack it. There are usually a lot of these challenges flying around the network. Some [[Network Security Solutions|security solutions]] even perform a sweep of entire IP ranges to recover information from hosts. Sometime due to stale DNS records, these authentication challenges can end up hitting our rogue device instead of the intended host.
Responder allows us to perform MITM attacks by poisoning the responses during NetNTLM authentication, tricking the client into talking to us instead of the actual server they wanted to connect to. 
On a real LAN, Responder will attempt to poison any **Link-Local Multicast Name Resolution** (LLMNR), **NetBIOS Name Service** (NBT-NS), and **Web Proxy Auto-Discovery** (WPAD) requests that are detected. On large Windows networks, these protocols allow hosts to perform their own local DNS resolution for all hosts on the same local network. Rather than overburdening network resources such as the DNS servers, hosts can first attempt to determine if the host they are looking for is on the same local network by sending out LLMNR requests and seeing if any hosts respond. The NBT-NS is the precursor protocol to LLMNR, and WPAD requests are made to try and find a proxy for future HTTP(S) connections.

Since these protocols rely on requests broadcasted on the local net, our rogue device would also receive these requests. Usually, these would simply be dropped since they were not intended for our host. However, Responder will actively listen to the requests and send poisoned responses telling the requesting host that our IP is associated with the requested hostname.
By poisoning these requests, Responder attempts to force the client to connect to our machine. In the same line, it starts to host several servers such as SMB, HTTP, SQL, and others to capture these requests and force authentication.

## Intercepting NetNTLM Challenge
Note that Responder essentially tries to win the race condition by poisoning the connections to ensure that we intercept the connection. This means that Responder is usually limited to poisoning authentication challenges on the local network.
Although Responder would be able to intercept and poison more authentication requests when executed from our rogue device connected to the LAN of an organisation, it is crucial to understand that **this behavior can be disruptive** and thus detected. By poisoning authentication request, normal network authentication attempts would fail, meaning users and services would not connect to these hosts and shares they intend to.
We can start responder with
```sh
sudo responder -I interfaceName
```
Responder will now listen for any LLMNR, NBTS, or WPAD requests that are coming in. And now all we have to do is leave it to do its thing, and wait for an authentication attempt to take place. 
If we were using our Rogue device we would probably leave it for a while to capture various responses. Once we have a couple we can start to perform some offline cracking of the responses in the hopes of recovering their associated NTLM passwords. If they have weak credentials, rules we know, or more info about the people working there we may just be able to crack them.
We paste the hash into a file, give it to either [[John The Ripper]] or [[Hashcat]] to crack, pray and we are golden
```sh
john --format=netntlmv2 hashed --wordlist=rockyou.txt 

hashcat -a 0 -m 5600 hashed rockyou.txt
```

# Microsoft Deployment Toolkit
Large organizations need tools to deploy and manage the infrastructure of the estate. In massive organizations, we can't have our IT using DVDs or even USB flash drives running around installing software on every single machine. Luckily, Microsoft already provides the tools required to manage the estate. However, we can exploit misconfigurations in these tools to also breach AD.

## MDT and SCCM
**Microsoft Deployment Toolkit** (MDT) is a Microsoft service that assists with automating the deployment of Microsoft OS. Large organizations use services such as MDT to help deploy new images in their estate more efficiently since the base images can be maintained and updated in a central location.
Usually, MDT is integrated with Microsoft's **System Center Configuration Manager** (SCCM), which manages all updates for all of Microsoft's applications, services, and OS. MDT is used for new deployments. Essentially it allows the IT team to preconfigure and manage boot images. Hence, if they need to configure a new machine, they just need to plug in a network cable, and everything happens automatically. They can make various changes to the boot image, such as already installing default software like Office365 and the organization's [[Antivirus|AV]] of choice. It can also ensure that the new build is updated the first time the installation runs.
SCCM can be seen as almost an expansion and the bigger brother to MDT. SCCM deals with the software after installed, it allows IT to review available updates to all software installed across the estate. The team can also test these patches in a sandbox environment to ensure they are stable before centrally deploying them to all domain-joined machines. 
However, anything that provides central management of infrastructure such as MDT and SCCM can also be targeted by attackers in an attempt to take over large portions of critical functions in the estate. Although MDT can be configured in various ways, we will focus on a configuration called Preboot Execution Environment (PXE) boot.

## PXE boot
Large orgs use PXE boot to allow new devices that are connected to the network to load and install the OS directly over a network connection. MDT can be used to create, manage, and host PXE boot images. PXE boot is usually integrated with the **Dynamic Host Configuration Protocol** (DHCP), which means that if DHCP assigns an IP lease, the host is allowed to request the PXE boot image and start the network OS installation process.
![[Pasted image 20241011020138.png]]
Once the process is performed, the client will use a TFTP connection to download the PXE boot image. We can exploit the PXE boot image for two different purposes:
- Inject a privilege escalation vector, such as Local Administrator account, to gain Administrative access to the OS once the PXE boot has been completed.
- Perform password scraping attacks to recover AD credentials used during the install.
We will focus on the latter. Attempting to recover the deployment service account associated with the MDT services during installation.

## PXE Boot Image Retrieval
The first piece of information regarding the PXE Boot preconfigure we would have received via DHCP is the IP of the MDT server. The second piece of information is the names of the BCD files. These files store the information relevant to the PXE Boots for the different types of architecture.
![[Pasted image 20241011021347.png]]
Usually, we would use TFTP to request each of these BCD files and enumerate the configuration for all of them. But for the sake of this technique, we will focus on the BCD file of the **x64** architecture. 

With this information now recovered from the DHCP, we can enumerate and retrieve the PXE Boot image. We will be using our connection with our machine on the inside (we should have one if we are trying this, can be rouge device) for the next steps.

To ensure that al users of the network can use SSH, we start by creating a folder and copying the [PowerPXE](https://github.com/wavestone-cdt/powerpxe) repo into this folder
```cmd
cd Documents
mkdir FolderName
copy C:\powerpxe FolderName\
cd FolderName
```
Now, we need to use TFTP and download our BCD file to read the configuration of the MDT server. TFTP is a bit trickier since we can't list files. So we instead send a file request, and the server will connect back to us via UDP to transfer the file. Hence, we need to be accurate when specifying files and file paths. The BCD files are always located in the /Tmp/ directory on the MDT server. We can initiate the TFTP transfer using the following
```cmd
tftp -i <MDT IP> GET "\Tmp\x64{F1...76}.bcd" conf.bcd
```
Now, with the BCD file recovered, we will be using PowerPXE to read its contents. It can automatically perform this type of attack but usually with varying results, so it is better to perform a manual approach. We will use the Get-WimFile function of PowerPXE to recover the locations of the PXE Boot images from the BCD file:
```cmd
powershell -executionpolicy bypass
```
```powershell
Import-Module .\PowerPXE.ps1
$BCDFile = "conf.bcd"
Get-WimFile -bcdFile $BCDFile
```
WIM files are bootable images in the **Windows Imaging Format** (WIM). Now that we have the location, we can again use TFTP to download this image
```powershell
tftp -i <MDT IP> GET "<PXE Boot Img Location>" pxeboot.wim
```
It may take a while as we are downloading an entire bootable file

## Recovering Credentials from a PXE Boot Image
Now that we have recovered the PXE Boot image, we can exfiltrate stored credentials. It should be noted that there are various attacks that we could stage. We could inject a local administrator user, so we have admin access as soon as the image boots, we could install the image to have a domain-joined machine. For more info [paper](https://www.riskinsight-wavestone.com/en/2020/01/taking-over-windows-workstations-pxe-laps/).
Sticking to exfiltration, we will use PowerPXE to recover the credentials, but we could also do this step manually by extracting the image and looking for the `bootstrap.ini` file, where these types of credentials are often stored. To do use PowerPXE we use
```powershell
Get-FindCredentials -WimFile pxeboot.wim
```
And presto, we have credentials

# Configuration Files
The last enumeration avenue we will explore is config files. Suppose we are lucky enough to cause a breach that gave us access to a host on the organization's network. In that case, configuration files are an excellent avenue to explore in an attempt to recover AD credentials. Depending on the host that was breached, various configuration files may be of value for enumeration:
- Web app config files
- Service config files
- Registry keys
- Centrally deployed apps
Several enumeration scripts, such as [Seatbelt](https://github.com/GhostPack/Seatbelt), can be used to automate this process.
## Config File Credentials
We will focus on a centrally deployed application this time. Usually, these applications need a method to authenticate to the domain during both the installation and execution phase. An example of such an application is McAfee Enterprise Endpoint Security, which organizations use as the EDR tool for security.
It embeds the credentials used during installation to connect back to the orchestrator in a file called `ma.db`. This database file can be retrieved an read with local access to the host to recover the associated AD service account. Once we find it we can copy it to our machine
```sh
scp pwndAdmin@AdminMchn.za.enterprise.com:C:/ProgramData/McAfee/Agent/DB/ma.db .
```
To read the database, we will use a tool called `sqlitebrowser`. 
```sh
sqlitebrowser ma.db
```
Using it, we will select Browse Data and focus on the `AGENT_REPOSITORIES` table
![[Pasted image 20241011025517.png]]
We are interested on the DOMAIN, AUTH_USER and AUTH_PASSWD field entries. Sadly, the password is encrypted. Fortunately, McAfee encrypts this field with a known key. And we have a [script](https://github.com/funoverip/mcafee-sitelist-pwd-decryption/blob/master/mcafee_sitelist_pwd_decrypt.py) that decodes it for us 
```
mcafee_decrypt.py jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==
```
And presto, we have a new set of credentials.

# Mitigation
We've are in boys. But we shouldn't have. So here are some things that organizations can do to prevent this things
- User awareness and training - The weakest link in the cybersecurity chain is almost always users. Training users and making them aware that they should be careful about disclosing sensitive information such as credentials and not trust suspicious emails reduces this attack surface.
- Limit the exposure of AD services and applications online - Not all applications must be accessible from the internet, especially those that support NTLM and LDAP authentication. Instead, these applications should be placed in an intranet that can be accessed through a VPN. The VPN can then support multi-factor authentication for added security.
- Enforce Network Access Control (NAC) - NAC can prevent attackers from connecting rogue devices on the network. However, it will require quite a bit of effort since legitimate devices will have to be white list.
- Enforce SMB Signing - By enforcing SMB signing, SMB relay attacks are not possible.
- Follow the principle of least privileges - In most cases, an attacker will be able to recover a set of AD credentials. By following the principle of least privilege, especially for credentials used for services, the risk associated with these credentials being compromised can be significantly reduced.