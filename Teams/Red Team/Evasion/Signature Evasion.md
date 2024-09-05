# Signature Identification
When identifying signatures, whether manually or automated, we must employ an iterative process to determine what byte a signature stars at. By recursively splitting a compiled binary in half and testing it, we can get a rough estimate of a byte-range to investigate further.
We can use the native utilities `head`, `dd`, or `split` to split a compiled binary. If an alert appears, we split it again, and repeat the testing until the we can no longer split accurately the binary. We can use a hex editor to view the end of the binary where the signature should be present.
## Automation
Due to the previous process being boring as fuck, we can automate it using scripts to split bytes over an interval for us. [Find-AVSignature](https://github.com/PowerShellMafia/PowerSploit/blob/master/AntivirusBypass/Find-AVSignature.ps1) will split a provided range of bytes through a given interval.
Although it requires less interaction than the previous task, it still requires an appropriate interval to be set to function properly. This script will also only observe strings of the binary when dropped to disk rather than scanning using the full functionality of the AV engine.
To solve this problem we can use other **FOSS** (Free and Open-Source Software) tools that leverage the engines themselves to scan the file, including [DefenderCheck](https://github.com/matterpreter/DefenderCheck), [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck), and [AMSITrigger](https://github.com/RythmStick/AMSITrigger). 

----


ThreatCheck is a fork of DefenderCheck and is arguably the most widely used/reliable of the three. To identify possible signatures, ThreatCheck leverages several anti-virus engines against split compiled binaries and reports where it believes bad bytes are present.
For our uses we only need to supply a file and optionally an engine, (Although we should use AMSITrigger when dealing with AMSI).
```powershell
ThreatCheck.exe -f virus.exe -e Defender
```
To efficiently use this tool we can identify any bad bytes that are first discovered then recursively break them and run the tool again until no signatures are identified.

---


As covered in [[Runtime Detection Evasion]], AMSI (Anti-Malware Scan Interface) leverages the runtime, making signatures harder to identify and resolve. ThreatCheck also does not support certain file types such as Powershell that AMSITrigger does.
AMSITrigger will leverage the AMSI engine and scan functions against a provided PowerShell script and report any specific sections of code it believes need to be alerted on.
```powershell
amsitrigger.exe -i code.ps1 -f 3
```

# Static Code-Based Signatures
Once we have identified a troublesome signature we need to decide how we want to deal with it. Depending on the strength and type of signature, it may be broken using a simple [[Obfuscation]], or it may require specific investigation and remedy. 
The [Layered Obfuscation Taxonomy Paper](https://cybersecurity.springeropen.com/track/pdf/10.1186/s42400-020-00049-3.pdf) covers the most reliable solutions as part of the **Obfuscating Methods** and **Obfuscating Classes** layer.

| **Obfuscation Method  <br>**  | **Purpose**                                                        |
| ----------------------------- | ------------------------------------------------------------------ |
| Method Proxy                  | Creates a proxy method or a replacement object                     |
| Method Scattering/Aggregation | Combine multiple methods into one or scatter a method into several |
| Method Clone                  | Create replicas of a method and randomly call each                 |

| **Obfuscation Method  <br>** | **Purpose**                                                          |
| ---------------------------- | -------------------------------------------------------------------- |
| Class Hierarchy Flattening   | Create proxies for classes using interfaces                          |
| Class Splitting/Coalescing   | Transfer local variables or instruction groups to another class      |
| Dropping Modifiers           | Remove class modifiers (public, private) and make all members public |
Looking at the tables, even though they may use a specific technical term, we can group them somewhat into methods applicable to any object or data structure.
The techniques **Class splitting/coalescing** and **methods scattering/aggregation** can be grouped into an overarching concept of ***splitting or merging*** any given OOP function.
Other techniques such as **dropping modifiers** or **method clone** can be grouped into an overarching concept of ***removing or obscuring*** identifiable information.

---


The methodology required to split or merge objects is very similar to the objective of [[Obfuscation#Object Concatenation|concatenation]]. The premise behind this concept is relatively easy, we are looking to create a new object function that can break the signature while maintaining the previous functionality.

---


The core concept behind removing Identifiable information is similar to [[Obfuscation#Protecting and Striping Identifiable Information|obscuring variable names]]. The thing now, is that we will be applying it to identified signatures in any objects including methods and classes. 
An example of this can be found in [[Mimikatz]] where an alert is generated for the string `wdigest.dll`. This can be solved by replacing the string with any random identifier changed throughout all instances of the string. This can be categorized in [paper](https://cybersecurity.springeropen.com/track/pdf/10.1186/s42400-020-00049-3.pdf) under the method proxy technique. 

# Static Property-Based Signatures
Various detection engines or analysts may consider different indicators rather than strings or static signatures to contribute to their hypothesis. Signatures can be attached to several file properties, including **hash, entropy author, name** or other identifiable information to be used individually or in conjunction. These can be used in sets such as [[Yara]] rules or [[Sigma]].
Some of these properties can be easily manipulated, while others are a bit more difficult, specially when dealing with pre-compiled closed-source applications.
Some other properties like [[Windows Internals#Portable Executable Format|PE headers]] or module properties can be used as indicators but these usually rely on an agent or other measures to detect.
## File Hashes
Also known as **Checksum** are used to identify a unique file. They are commonly used to verify a file's authenticity or its known purposes. File hashes are generally arbitrary to modify and are changed with any slight modification. 
If we have access to the source for an application, we can modify any arbitrary section of the code and re-compile it to create a new hash. But, when dealing with signed or closed-source applications, we must employ **Bit-flipping**.
It is a common cryptographic attack that will mutate a given application by flipping and testing each possible bit until it finds a viable bit. By flipping one viable bit, it will change the signature and hash of the application while maintaining all functionality.
We can use a simple script to create a bit-flipped list by testing each bit and creating a new mutated variant.
```python
import sys

orig = list(open(sys.argv[1], "rb").read())

i = 0
while i < len(orig):
	current = list(orig)
	current[i] = chr(ord(current[i]) ^ 0xde)
	path = "%d.exe" % i
	
	output = "".join(str(e) for e in current)
	open(path, "wb").write(output)
	i += 1
	
print("done")
```
Once this list is created, we must search for an intact unique properties of the file. For example, if we were flipping `msbuild`, we need to use `signtool` to search for a file with a usable certificate. This will guarantee that the functionality of the file is not broken, and the application will maintain its signed attribution. 
We can use a batch script to loop through the bit-flipped list and verify functional variants.
```powershell
FOR /L %%A IN (1,1,10000) DO (
	signtool verify /v /a flipped\\%%A.exe
)
```
Although very good, it takes a lot of time and will be useful until the hash is discovered.

## Entropy
The randomness of a file that is used to determine whether it contains hidden data or suspicious scripts. EDRs and other scanners often leverage entropy to identify potential suspicious files or contribute to an overall malicious score.
It can be problematic for [[Obfuscation|obfuscated]] scripts, specifically when obscuring identifiable information, such as variables or functions.
To lower entropy we can replace random identifiers with randomly selected English words, ej. We could change `1kfbsd7` to `cheese`. This way, when checking for the entropy of the file, it will have a lesser chance to flag like an encrypted or obfuscated file.

# Behavioral Signatures
Obfuscating functions and properties can achieve a lot with minimal modification. Even after breaking static signatures attached to a file, modern engines may still observe the behavior and functionality of the binary. 
As we [[Antivirus#Heuristic and Behavioral Detection|know]] modern AV engines will employ two common methods to detect behavior: **observing imports** and **hooking known malicious calls**. While imports can be obfuscated or modified with minimal requirements, <u>unhooking requires complex techniques</u>. Because of the prevalence of API calls specifically, observing these functions can be a significant factor in determining if a file is suspicious, along with other behavioral tests.

Normally API calls and other functions native to an OS require a pointer to a function address and a structure to utilize them. Structures for functions are simple, they are located in **import libraries** such as `kernel32` or `ntdll` that store function structures and other core information for Windows.

The most significant issue to import functions is the function addresses. Obtaining a pointer may seem straightforward, although because of **ASLR** (Address Space Layout Randomization), function addresses are dynamic and must be found.
Rather than altering code at runtime, the **Windows loader** `windows.h` is employed. At runtime, the loader will map all modules to process address space and list all functions from each. 

One of the most crucial functions of the Windows loader is the **IAT** (Import Address Table). The IAT will store function addresses for all imported functions that can assign a pointer for the function.
The IAT is stored in the PE header `IMAGE_OPTIONAL_HEADER` and is filled by the Windows loader at runtime. The Windows loader obtains the function addresses or, more precisely, thunks from a pointer table, accessed from an API call or thunk table.

---

The import table can provide a lot of insight into the functionality of a binary that can be detrimental to us. Because of this we need to prevent our functions from appearing in the IAT. 
The thunk table is not the only way to obtain a pointer for a function address. We can also utilize an API call to obtain the function address from the import library itself. This technique is known as **dynamic loading** and can be used to avoid the IAT and minimize the use of the Windows loader. 
We will write our structures and create new arbitrary names for functions to employ dynamic loading.
At a high level, we can break up dynamic loading in C into
1. Defining the structure of the call
2. Obtain the handle of the module the call address is present in
3. Obtain the process address of the call
4. Use the newly created call

---

To begin dynamically loading an API call, we must first define a structure for the call before the main function. The call structure will define any inputs or outputs that may be required for the call to function. We can find structures for a specific call on the Microsoft documentation. For example, the structure for `GetComputerNameA` found [here](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getcomputernamea). Because we are implementing this as a new call in C, the syntax must change a little, but the structure stays the same, as seen below.
```C
// 1. Defining the structure of the call 
typedef BOOL (WINAPI* myNotGetComputerNameA)(
	LPSTR lpBuffer,
	LPDWORD nSize
);
```
To access the address of the API call, we must first load the library where it is defined. We will define this in the main function. This is commonly `kernel32.dll` or `ntdll.dll` for any Windows API calls. 
```C
// 2. Obtain the handle of the module the call is present in
HMODULE hkernel32 = LoadLibraryA("kernel32.dll");
```
Using the previously loaded module, we can obtain the process address for the specified API call. This will come directly after the `LoadLibrary` call. we can store this call by casting it along with the previously defined structure. Below is an example of the syntax required to obtain the API call.
```C
// 3. Obtain the process address of the call
myNotGetComputerNameA notGetComputerNameA = (myNotGetComputerNameA) GetProcAddress(hkernel32, "GetComputerNameA");
```
Although this method solves many concerns and problems, there are still several considerations that must be noted. Firstly, `GetProcAddress` and `LoadLibraryA` are still present in the IAT, and even tho they are not a direct indicator it can lead to suspicion. This problem can be solved by using **PIC** (Position Independent Code). Modern agents will also hook specific functions and monitor kernel interactions, this can be solved using [[API unhooking]]. 
