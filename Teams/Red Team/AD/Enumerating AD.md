Now that we have our first set of [[Breaching AD|valid AD credentials]], we can go ahead an explore the different methods to enumerate [[Active Directory|AD]]. During an engagement, enumeration is pretty entangled with both [[Exploiting Active Directory|exploitation]] and [[Lateral Movement and Pivoting|Lateral Movement and Pivoting]], as once an attack vector is shown by the enumeration phase, we can exploit it, move, and then have to perform enumeration again from our new position.

# Credential Injection
Obtaining the credentials is often a step that we can do without compromising a domain-joined machine. However specific enumeration techniques may require a particular setup to work.

## Windows vs Linux
We can get very far doing AD enumeration from a Kali machine. Still, if we genuinely want to do in-depth enumeration and even exploitation, we need to understand and mimic our enemy. Thus, we need a Windows machine. This will allows us to use several built-in methods to stage our enumeration and exploits. Like the `runas.exe` bin.

## Runas
If we ever have AD credentials but nowhere to log in with them, Runas may be our answer.
In security assessments, we will often have network access and have just discovered AD credentials but no means or privileges to create a new domain-joined machine. So we need the ability to use those credentials on a Windows machine we control.
If we have the AD credentials in the format of `<username>:<password>`, we can use Runas, a legitimate Windows binary, to inject the credentials into memory. The usual Runas command would something like
```cmd
runas.exe /netonly /user:<domain>\<username> cmd.exe
```
- `/netonly` - Since we are not domain-joined, we want to load the credentials for network authentication but not authenticate against a domain controller. So commands executed locally on the computer will run in the context of our standard Windows account, but any network connections will occur using the account specified here.
- `/user` - Here, we provide the details of the domain and the username. It is always a safe bet to use the **Fully Qualified Domain Name** (FQDN) instead of just the NetBIOS name of the domain since this will help with the resolution.
- `cmd.exe` - The program we want to execute once the credentials are injected. We can of course use whatever we want, but the safest bet is cmd.exe since we can then use that to launch whatever we want, with the injected credentials.
Note, that because we used the `/netonly` parameter, the credentials will not be verified directly by a domain controller, so it will accept any password. We still need to confirm that the network credentials are loaded successfully and correctly.
If we use our own Windows machine, we should make sure that we run our cmd as Administrator. This will inject an Administrator token into CMD. If we run tools that require local Administrative privileges from our Runas spawned CMD, the token will already be available. This does not give us administrative privileges on the network, but will ensure that any local commands we execute, will execute with administrative privileges.

## DNS
After providing the password, a new cmd prompt window will open. Now we still need to verify that our credentials are working. The most surefire way to do this is to list SYSVOL. Any AD account, not matter how low-privileged, can read the contents of the SYSVOL directory.
SYSVOL is a folder that exists on all domain controllers. It is a shared folder storing the GPOs and information along with any other domain related scripts. It is an essential component for AD since it delivers these GPOs to all computers on the domain. Domain-joined computers can then read these GPOs and apply the applicable ones, making domain-wide configuration changes from a central location.

Before we can list SYSVOL, we need to configure our DNS. Sometimes it will be configured for us automatically through DHCP or a VPN connection, but not always. Our safest bet for a DNS server is usually a domain controller. Using that, we can execute
```powershell
$dnsip = "<DC IP>"
$index = Get-NetAdapter -Name '<Interface>' | Select-Object -ExpandProperty 'ifIndex'
Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $dnsip
```

## IP vs Hostnames
To resolve or to not resolve, that is the question, so what is the difference between `dir \\za.enterprise.com\SYSVOL` and `dir \\<DC IP>\SYSVOL`?

When providing the hostname, network authentication will first attempt to perform Kerberos authentication. Since Kerberos authentication uses hostnames embedded in the tickets, if we provide the IP instead, we can force the authentication type to be NTLM. 
It is good to keep this in mind, as these slight differences can help us to remain in out ghost playthrough. Some companies will be monitoring for [[Lateral Movement and Pivoting#Overpass-the-hash / Pass-the-Key|OverPass-]] and [[Lateral Movement and Pivoting#Pass-the-Hash|Pass-the-Hash]] Attacks. Forcing NTLM authentication is a good trick to have in the book to avoid detection in these cases.

## Using Injected Credentials
Once we have injected our credentials, we can begin. With the `\netonly` option, all network communications will use these injected credential for authentication. This includes all network communications of applications executed from that command prompt window.
This is where it becomes interesting. If we ever have a case where an MS SQL database used Windows Authentication, and we were not domain-joined, we could start MS SQL studio from our injected command prompt, and even though it shows our local username, click Log In, and it will use the AD credentials in the background to authenticate.

# Enumeration Through MMC
This method makes use of a GUI, so we will be needing a connection through RDP or opening the application on our machine through injecting the credentials. We will be using **Microsoft Management Console** (MMC) with the **Remote Server Administration Tools'** (RSAT) AD Snap-Ins. If we are using our own Windows Machine, we need to install RSAT.
We can then start `mmc.exe`. If we try to run it as is from our machine it would not work as our local account cannot authenticate into the domain, so we need to use `runas` to open it.
In MMC, we can now attach the AD RSAT Snap-In
1. **File** > **Add/Remove Snap-In**
2. Select and **Add** all three Active Directory Snap-Ins
3. Click through errors and warnings :D
4. Right-click on **Active Directory Domains and Trusts** and select **Change Forest**
5. Enter the domain hostname as the **Root domain** and click OK
6. Right-click on **Active Directory Sites and Services** and select **Change Forest**
7. Enter the domain hostname as the **Root domain** and click OK
8. Right-click on **Active Directory Users and Compute**rs and select **Change Forest**
9. Enter the domain hostname as the **Root domain** and click OK
10. Right-click on **Active Directory Users and Computers** in the left-hand pane
11. Click on **View** > **Advanced Features**
If everything is correct, our MMC should now be pointed to, and authenticated against, the target Domain.

## Users and Computers
We can go down and take a look at the AD structure. In this case we will focus on AD Users and Computers. Expanding on the snap-in of Users and Computers and in the domain hostname, we can see the initial Organizational Unit structure. We can go and see the people that are inside the AD, as well as the Admin accounts, how the employees are divided based on sectors, computers as workstations, and computers for the server, among a lot of other things.

If we had the relevant permissions, we could also use MMC to directly make changes to AD, such as changing the user's password or adding an account to a specific group. 

## Adv. and Dis.
Now enumerating through MMC has both advantages and disadvantages. For starters
- It provides a pretty good view of the AD environment
- We can quickly search for different AD objects
- We can directly update existing AD objects or add new ones (with the necessary permissions).
But in the other hand
- The GUI requires either RDP access to the machine where it is executed or connecting through a machine of ours
- Although searching for a single object is quick, gathering various AD wide properties or attributes is not possible.

# Enumeration Through cmd
There are times when we just need to perform a quick AD lookup, and cmd is perfect for that. CMD is perfect for when we don't have RDP access to a system, defenders are monitoring for PowerShell use, and we need to perform our AD enumeration through a **Remote Access Trojan** (RAT). It can even be helpful to embed a couple of simple AD enumeration commands in our phishing payload to help us gain the vital information that can help us to stage the final attack.
CMD has a built-in command that we can use to enumerate information about the AD, `net`.
The `net` command is a handy tool to enumerate information about the local system and AD. 
[Documentation](https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/net-commands-on-operating-systems)

## Users
We can use the `net` command to list all users in the AD domain by using the `user` sub-option
```cmd
net user /domain
```
We can also use this sub-option to enumerate more detailed information about a single user
```cmd
net user name.surname /domain
```
Note that if the user is only part of a small number of AD groups, this command will be able to show us group memberships. However, usually, after more than ten group memberships, the command will fail to list them all.

## Groups
We can use the `net` command to enumerate the groups of the domain by using the `group` sub-option:
```cmd
net group /domain
```
We could also enumerate more details such as members of a group by specifying the group in the same command.
```cmd
net group "Tier 1 Admins" /domain
```

## Password Policy
We can also enumerate the password policy of the domain by using
```cmd
net accounts /domain
```
This can give us some pretty juicy info.
- **Length of password history maintained**: So how many unique passwords must the user provide before they can reuse an old password.
- The lockout threshold for incorrect password attempts, and for how long it will be locked
- The minimum length of the password
- Maximum age a password is allowed to have before having to be reset

This could all help us to stage our attacks, thanks to this we can know if we have only number of chances to brute force a password or if we need to use a certain length of passwords for our wordlist.

## Adv and Dis
- No additional or external tooling is required, these are simple commands that every computer has, and are often not monitored for by the Blue team
- We don't need GUI
- VBScript and other macro languages that are often used for phishing payloads support these commands natively, so they can be used to enumerate initial information regarding AD before more specific payloads are crafted

- The `net` commands must be executed from a domain-joined machine. If the machine is not domain-joined, it will default to the WORKGROUP domain.
- the `net` commands may not show all information. For example if a user is a member of more than ten groups, some will be cut out.

# Enumeration Through PowerShell
Powershell is the upgrade of CMD. While PowerShell has all the standard functionality cmd provides, it also provides access to cmdlets, which are .NET classes to perform specific functions. While we can write our own cmdlets, like [[Powerview]], we can already get very far by using the built-in ones.
Since we installed the AD-RSAT tooling, it automatically installs the associated cmdlets for us.
[AD cmdlets](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps)

## Users
We can enumerate AD users
```powershell
Get-ADUser -Identity name.surname -Server za.enterprise.com -Properties *
```
The parameters used are for:
- `-Identity` The account name
- `-Properties` Which properties associated with the account will be show, in this case all (`*`)
- `-Server` If we are not domain-joined, we can use this parameter to point it to our DC and use `runas`
For most of these cmdlets, we can also use the `-Filter` parameter that allows more control over enumeration and use the `Format-Table` cmdlet to display the results neatly:
```powershell
Get-ADUser -Filter 'Name -like "*.smith"' -Server za.enterprise.com | Format-Table Name,SamAccountName -A
```

## Groups
We can enumerate Groups with
```powershell
Get-ADGroup -Identity Administrators -Server za.enterprise.com
```
We can also enumerate group membership using
```powershell
Get-ADGroupMember -Identity Administrators -Server za.enterprise.com
```

## AD Objects
A more generic search for any AD object can be performed using the `Get-ADObject` cmdlet. For example, if we were looking for all AD objects that were changed after a specific date we would use
```powershell
$Date = New-Object DateTime(2024, 01, 13, 23, 59, 59)
Get-ADObject -Filter 'whenChanged -gt $DAte' -includeDeletedObjects -Server za.enterprise.com
```
If we wanted to, for example, perform a password spraying attack without locking out accounts, we can enumerate for accounts that have `badPwdCount` greater than 0, to avoid these accounts in our attack
```powershell
Get-ADObject -Filter 'badPwdCount -gt 0'
```
This will only show users in the network that mistyped their passwords a couple of times.

## Domains
We can retrieve additional information about the specific domain
```powershell
Get-ADDomain 
```

## Altering AD Objects
Some cmdlets even allow us to create new or alter existing AD objects. However, we only enumerate here, for exploitation check [[Exploiting Active Directory|here]].
But one quick example could be to force change the password of our AD user
```powershell
Set-AdAccountPassword -Identity user.surname -Server za.enterprise.com -OldPassword (ConvertTo-SecureString -AsPlainText "oldpasswd" -force) -NewPassword (ConvertTo-SecureString -AsPlainText "newpasswd" -Force)
```


## Adv and Dis
- Powershell cmdlets can enumerate significantly more information than the net commands from the cmd
- We can specify the server and domain to execute these commands using `runas` from a non-domain-joined machine
- We can create our own cmdlets to enumerate specific information
- We can use the AD-RSAT cmdlets to directly change AD objects, such as resetting passwords or adding a user to a specific group

- Powershell is one of the most used technologies for hacking, so it is highly more likely to be monitored than cmd
- We have to install the AD-RSAT tooling or use other, potentially detectable, scripts for PowerShell enumeration

# Enumeration Through [[Bloodhound]]
## Sharphound
Sharphound is the enumeration tool of Bloodhound. It is used to enumerate the AD information that can then be visually displayed in the GUI of Bloodhound.
There are three different Sharphound collectors
- **Sharphound.ps1** - PowerShell script for running Sharphound. However, the latest release of Sharphound has stopped realising the Powershell script version. This version is good to use with RATs since the script can be loaded directly into memory, evading on-disk AV scans.
- **Sharphound.exe** - A windows executable version for running Sharphound.
- **AzureHound.ps1** - Powershell script for running Sharphound for Azure instances. Bloodhound can ingest data enumerated from Azure to find attack paths related to the configuration of Azure Identity and Access Management.

When using these collector scripts on an engagement, there is a high likelihood that these files will be detected as malware and raise an alert to the blue team. This is again where our Windows machine that is non-domain-joined can assist. We can use the `runas` command to inject the AD credentials and point Sharphound to a DC. Since we control this Windows machine, we can either disable the AV or create exceptions for specific files or folders.
We can use Sharphound in the following way
```cmd
Sharphound.exe --CollectionMethods <Methods> --Domain za.enterprise.com --ExcludeDCs
```
- `--CollectionMethods` - Determines what kind of data Sharphound will collect. The most common options are Default or All. Also, since Sharphound caches information, once the first run has been completed, we can only use the Session collection method to retrieve new user sessions to speed up the process.
- `--Domain` - Here, we specify the domain we want to enumerate. In some instances, we may want to enumerate a parent or other domain that has trust with our existing domain.
- `--ExcludeDCs` - This will instruct Sharphound not to touch domain controllers, which reduces the likelihood that the Sharphound run will raise an alert.
We can find other parameters [here](https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound-all-flags.html). 

Once we've gathered the information we can feed the ZIP to Bloodhound so it can show us the attack paths visually.

## Bloodhound
Bloodhound uses `Neo4j` as its backend database and graphing system. Neo4j is a graph database management system. 
Before we start Bloodhound, we need to load Neo4j
```sh
neo4j console start
```
Then, in another terminal, we run `bloodhound --no-sandbox`. This will take us to the authentication GUI. We log in with our default credentials `neo4j:neo4j` and drag-and-drop our ZIP into bloodhound. It will show that it is extracting the files and initiating the import.

## Attack Paths
There are several attack paths that Bloodhound can show. Pressing the three stripes next to "Search for a node" will show the options. The first tab shows us information regarding our current imports.
First we will look at Node Info. We must first select a node, we can search for one in the bar above. We can see that there is a significant amount of information returned regarding our use. Each of the categories provides the following information:
- **Overview** - Provides summaries information such as the number of active sessions the account has and if it can reach high-value targets.
- **Node Properties** - Show information regarding the AD account, such as the display name and the title
- **Extra Properties** - Provides more detailed AD information, such as the distinguished name and when the account was created.
- **Group Membership** - Shows information regarding the groups that the account is a member of
- **Local Admin Rights** - Provides information on domain-joined hosts where the account has administrative privileges
- **Execution Rights** - Provides information on special privileges such as the ability to RDP into a machine
- **Outbound Control Rights** - Shows information regarding AD objects where this account has permissions to modify their attributes
- **Inbound Control Rights** - Provides information regarding AD objects that can modify the attributes of this account.
For more information in each category, we can press the number next to the information query, adding the objects to the graph and allowing us to display things that we want.

Next we can take a look at the Analysis. Tese are queries that the creators of Bloodhound have written themselves to enumerate helpful information.
Under the Domain Information section, we can run the Find all Domain Admins query. Every icon we see is called node, and the lines are called edges.

Each AD object that was discussed before can be a node in Bloodhound, and each will have a different icon depicting the type of object it is. If we want to formulate an attack path, we need to look at the available edges between position and privileges we have and where we want to go. Bloodhound has various available edges that can be accessed by the filter icon.
![[Pasted image 20241015022628.png]]
These are also constantly being updated as new attack vectors are discovered. We can run a search in Bloodhound to enumerate an attack path. 
![[Pasted image 20241015024515.png]]
We can put set start node as our AD username, and our End node as some kind of administrator group, and it will show us what is the attack path to follow to reach that point.
If we are interested in any exploits associated with each edge, here we have [paper](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html).

## Session Data Only
The structure of AD does not change very often in large organizations. There may be a couple of new employees, but the overall structure of OUs, Groups, Users and permissions will remain relatively the same.
However, the one thing that does change constantly is active sessions and LogOn events. Since Sharphound creates a point-in-time snapshot of the AD structure, active session data is not always accurate since some users may have already logged off their sessions or new ones might have logged on. This is an essential thing to note and is why we would want to execute Sharphound at regular intervals.
A good approach is to execute Sharphound with the "All" collection at the start of our assessment and then execute Sharphound at least twice a day using the "Session" collection method. This will provide us with new session data and ensure that these runs are faster since they do not enumerate the entire AD structure again. The best times to execute these runs are around 10:00, when users have their coffee, and around 14:00 when they get back from their lunch breaks, but before home.

## Adv and Dis
- Provides an offline GUI for AD enumeration
- Has the ability to show attack paths for the enumerated AD information
- Provides more profound insights into AD objects that usually require several manual queries to recover

- Requires the execution of Sharphound, which is noisy and can often be detected by AV or EDR solutions.


# Additional Knowledege
- **[LDAP enumeration](https://book.hacktricks.xyz/pentesting/pentesting-ldap)** - Any valid AD credential pair should be able to bind to a Domain Controller's LDAP interface. This will allow you to write LDAP search queries to enumerate information regarding the AD objects in the domain.
- **[PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)** - PowerView is a recon script part of the [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) project. Although this project is no longer receiving support, scripts such as PowerView can be incredibly useful to perform semi-manual enumeration of AD objects in a pinch.
- **[Windows Management Instrumentation (WMI)](https://0xinfection.github.io/posts/wmi-ad-enum/)** - WMI can be used to enumerate information from Windows hosts. It has a provider called "root\directory\ldap" that can be used to interact with AD. We can use this provider and WMI in PowerShell to perform AD enumeration.
