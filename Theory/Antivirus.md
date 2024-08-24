# Features
## Scanner
The scanner features is included in most AV products. Available on real-time or on-demand, this feature must support the most known malicious file types to detect and remove the threat. In addition, it also may support other types of scanning depending  on the AV software, including vulnerabilities, emails, Windows memory and Windows Registry.

## Detection techniques 
There are various detection techniques that the antivirus uses, including:
- **Signature-Based detection**: When an infected file is analyzed by the AV and it confirms it as malicious, then it's signature is registered in the database. The AV then compares a scanned file with a database of known signatures for possible attacks or malware, and if they match it is deemed to be a threat 
- **Heuristic-Based detection**: Uses machine learning to decide whether we have the malicious file or not. It scans and statically analyses in real-time in order to find suspicious properties in the application's code or check whether it uses uncommon Windows or system APIs. It may or may not rely on signature-based detection, depending on the implementation of the AV.
- **Behavior-Based detection**: This relies on monitoring and examining the execution of the applications to find abnormal behaviors and uncommon activities, such as creating/updating values in registry keys, killing/creating processes, etc.
More in depth [[Antivirus#Techniques explained|here]].

## Compressors and Archives
The "Compressors and Archives" feature should be included in any AV software. It must support and be able to deal with various system file types, including compressed or archived files: ZIP, TGZ ,7z, XAR, RAR, etc. Malicious code often tries to evade host-based security solutions by hiding in compressed files. For this reason, AV software must decompress and scan through all files before a user opens a file within the archive.

## [[Windows Internals#Portable Executable Format|PE]] parsing and Unpackers
Malware hides and packs its malicious code by compressing and encrypting it within a payload. It decompresses and decrypts itself during runtime to make it harder to perform static analysis. Thus, AV software must be able to detect and unpack most of the known packers (UPX, Armadillo, ASPack, etc.) before runtime for static analysis.
Malware developers use various techniques, such as Packing, to shrink the size and change the malicious file's structure. Packing compresses the original executable file to make it harder to analyze. Therefore, AV software must have an unpacker feature to unpack protected or compressed executable files into the original code.

## Emulators
An emulator is an AV feature that does further analysis on suspicious files. Once an emulator receives a request, the emulator runs the suspect (exe, DLL, PDF, etc.) files in a virtualized and controlled environment. It monitors the executable file's behavior during the execution, including the Windows API's calls, Registry, and other Windows files. The following are things that the emulator may collect:
- API calls
- Memory dumps
- Filesystem modifications
- Log events
- Running processes
- Web requests

## Others
The following are some other common features found in AV:
- Self-protection driver to guard against malware attacking the actual AV
- Firewall and network inspection functionality
- Command-line and graphical interface tools
- A daemon or service
- A management console

# Techniques explained
## Static Detection
Based on predefined signatures of malicious files. Simply, it uses pattern-matching techniques in the detection, such as finding a unique string, CRC (Checksums), sequence of bytecode/Hex values, and cryptographic hashes (MD5, SHA1, etc.)
It then performs a set of comparisons between existing files, within the operating system and a database of signatures. If the signature exists in the database, then it is considered malicious. This method is effective against static malware.
Although good, signature detection can be easily bypassed by just modifying the malware a little bit, as it will change completely the signature. 

---


Now, checking the signature of the malware is not always going to work, so we can also try to use [[Yara]] rules for static detection. To create a rule we need to examine and analyze the malware, based on these findings we can write a rule to counter it. 
For example let's say that we have a malware that tries to remove system32, we could create a Yara rule to flag every file that includes this string (in a real scenario we could use something like registry keys, specific commands, etc.). The rule would be something like
```Yara
rule demo_rule{
	strings:
		$a = "C:\\Windows\\System32"
	condition:
	$a
}
```
We then store this rule with a `.yara` extension and run a static scan using this rule. Now this of course would get a ton of false positives, as legitimate files could include this directory, so we can refine further our rule. We can, for example, add magic numbers to only include `.exe` files (`0x4D 0x5A` or `MZ`).
```Yara
rule demo_rule{
	strings:
		$a = "C:\\Windows\\System32"
		$b = "MZ"
	condition:
	$b at 0 and $a
}
```
Now, we are going to check if the characters `MZ` are at the 0 location, indicating that it is an `.exe` file, if both that and the existence of our directory appear then the rule is going to flag it. 

## Dynamic Detection
More complicated than static detection, it focuses more on checking files at runtime using different methods. 
The first being monitoring Windows APIs. The detection engine inspects windows application calls and monitors Windows API call using Windows Hooks.
The other method is [[Sandbox Evasion|Sandboxing]]. An isolated virtualized environment used to run malicious files separated from the host computer, to analyze how the software acts on the system. If it confirms to be malicious a unique signature and rule will be created and it will be pushed into the database.
This latter detection, comes with drawbacks, because we need to execute the malicious software in a virtual space for a limited time to protect the system. We can implement a way for the software to not work within this simulated environment, by checking if the system spawns a real process of executing the software before doing anything malicious, or we could just make the software wait a little before executing, making it appear to be harmless.

## Heuristic and Behavioral Detection
Heuristic and behavioral detection have become essential in today's modern AV products. The Heuristic analysis includes various techniques, including static and dynamic heuristic methods
- Static heuristic analysis is a process of decompiling and extracting the source code of the malicious software. Then, it is compared to other well-known virus source codes from its database. If a match meets or exceeds a threshold it is flagged
- Dynamic heuristic analysis is based on predefined behavioral rules. Security researchers analyzed suspicious software in isolated and secured environments. Based on their findings, they flagged the software as malicious. Then, behavioral rules are created to match the software's malicious activities.
Some examples of behavioral rules may be
- If a process tries to interact with the LSASS.exe process that contains user's NTLM hashes Kerberos tgt, etc.
- If a process opens a listening port and waits to receive commands from a C2 server.

# Fingerprinting AV
Once we gain initial access to a machine, we do not know which AV is installed, and it is very important to find that out. As knowing this is also quite helpful in creating the same environments to test bypass techniques. 
Some common AVs are

| **Antivirus Name** | **Service Name**                  | **Process Name**                   |
| ------------------ | --------------------------------- | ---------------------------------- |
| Microsoft Defender | WinDefend                         | MSMpEng.exe                        |
| Trend Micro        | TMBMSRV                           | TMBMSRV.exe                        |
| Avira              | AntivirService, Avira.ServiceHost | avguard.exe, Avira.ServiceHost.exe |
| Bitdefender        | VSSERV                            | bdagent.exe, vsserv.exe            |
| Kaspersky          | AVP<Version #>                    | avp.exe, ksde.exe                  |
| AVG                | AVG Antivirus                     | AVGSvc.exe                         |
| Norton             | Norton Security                   | NortonSecurity.exe                 |
| McAfee             | McAPExe, Mfemms                   | MCAPExe.exe, mfemms.exe            |
| Panda              | PavPrSvr                          | PavPrSvr.exe                       |
| Avast              | Avast Antivirus                   | afwServ.exe, AvastSvc.exe          |
## SharpEDRChecker
One way to fingerprint AV is by using public tools such as [SharpEDRChecker](https://github.com/PwnDexter/SharpEDRChecker). It is written in C# and performs various checks on a target machine, including checks for AV software, like running processes, file's metadata, loaded DLL files, Registry keys, services, directories, and files.
Note that this may be flagged as malicious as it does various checks and APIs calls.

## C# Fingerprint checks
Another way to enumerate AV software is by coding our own program. We can create a simple program that checks for the running processes, and compares their name with the ones we already know, to try and find if any AV is currently running. A simple and straightforward code could be something like this
```python
import psutil as ps
AV_Check = {
        "MsMpEng.exe", "AdAwareService.exe", "afwServ.exe", "avguard.exe", "AVGSvc.exe",
        "bdagent.exe", "BullGuardCore.exe", "ekrn.exe", "fshoster32.exe", "GDScan.exe",
        "avp.exe", "K7CrvSvc.exe", "McAPExe.exe", "NortonSecurity.exe", "PavFnSvr.exe",
        "SavService.exe", "EnterpriseService.exe", "WRSA.exe", "ZAPrivacyService.exe"
        }

print("Running...")

for pid in ps.pids():
    name = ps.Process(pid).name()
    if(name in AV_Check):
        print("Found: " + name)

print("DONE")
```

