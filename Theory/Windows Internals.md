# Processes
Each process provides the resources needed to execute a program. A process has a virtual address space, executable code, open handles to system objects, a security context, a unique process identifier, environment variables, a priority class, minimum and maximum working set sizes and at least one thread of execution.
We can target processes to [[Host Evasion|evade detections]] and hide malware as legitimate processes. Some potential attack vectors could be
- Process Injection ([T1055](https://attack.mitre.org/techniques/T1055/))
- Process Hollowing ([T1055.012](https://attack.mitre.org/techniques/T1055/012/))
- Process Masquerading ([T1055.013](https://attack.mitre.org/techniques/T1055/013/))

---

| **Process Component  <br>**   | **Purpose**                                                                                     |
| ----------------------------- | ----------------------------------------------------------------------------------------------- |
| Private Virtual Address Space | Virtual memory addresses that the process is allocated.                                         |
| Executable Program            | Defines code and data stored in the virtual address space.                                      |
| Open Handles                  | Defines handles to system resources accessible to the process.                                  |
| Security Context              | The access token defines the user, security groups, privileges, and other security information. |
| Process ID                    | Unique numerical identifier of the process.                                                     |
| Threads                       | Section of a process scheduled for execution.                                                   |
We can also explain a process at a lower level as it resides in the virtual address space. The table and diagram below depict what a process looks like in memory.

| **Component  <br>** | **Purpose**                                   |
| ------------------- | --------------------------------------------- |
| Code                | Code to be executed by the process.           |
| Global Variables    | Stored variables.                             |
| Process Heap        | Defines the heap where data is stored.        |
| Process Resources   | Defines further resources of the process.     |
| Environment Block   | Data structure to define process information. |
This information is excellent to have when delving deeper into exploiting processes. We can use the task manager in order to observer these processes, by reporting on many components and information about a process

| **Value/Component** | **Purpose **                                                             | **Example** |
| ------------------- | ------------------------------------------------------------------------ | ----------- |
| Name                | Define the name of the process, typically inherited from the application | conhost.exe |
| PID                 | Unique numerical value to identify the process                           | 7408        |
| Status              | Determines how the process is running (running, suspended, etc.)         | Running     |
| User name           | User that initiated the process. Can denote privilege of the process     | SYSTEM      |
These are what we would be interacting with the most as an attacker. There are multiple utilities available that make observing proceses easier like [[Process Hacker 2]], [[Process Explorer]], and [[Procmon]]. 

# Threads
A thread is an executable unit employed by a process and scheduled based on device factors. Device factors can vary based on CPU and memory specifications, priority and logical factors, etc. 
Simply put a thread controls the execution of a process, due to this, the thread can be abused on its own to aid in code execution, or it is more widely use to chain with other API calls as part of other techniques.
Threads share the same details and resources as their parent process, such as code, global variables, etc. But they also have their unique values and data

| **Component**        | **Purpose**                                                                      |
| -------------------- | -------------------------------------------------------------------------------- |
| Stack                | All data relevant and specific to the thread (exceptions, procedure calls, etc.) |
| Thread Local Storage | Pointers for allocating storage to a unique data environment                     |
| Stack Argument       | Unique value assigned to each thread                                             |
| Context Structure    | Holds machine register values maintained by the kernel                           |

# Virtual Memory
Virtual Memory is a critical component of how windows internals work and interact with each other. Virtual memory allows other internal components to interact with memory as if it was physical memory without the risk of collisions between applications.
Virtual memory provides each process with a private virtual address space. A memory manager is used to translate virtual addresses to physical addresses. By having a private virtual address space and not directly writing to physical memory, processes have less risk of causing damage.
The Memory manager will also use **pages** or **transfers** to handle memory. Applications may use more virtual memory than physical memory allocated, thus the memory manager will transfer or page virtual memory to the disk to solve this problem.

The theoretical maximum virtual address space is 4 GB on a 32-bit x86 system. This address space is split in half, the lower half (0x00000000-0x7FFFFFFFF) is allocated to process as mentioned above, while the upper half (0x80000000-0xFFFFFFFF) is allocated to OS memory utilization. Administrators can alter this allocation layout for applications that require a larger address space through settings (`increaseUserVA`) or the AWE (Address Windowing Extensions)

On a 64-bit modern system the theoretical maximum space is 256 TB. The same address layout ratio from the 32-bit system is used for the 64-bit system. Most issue that require setting or AWE are resolved with the increased theoretical maximum. 

Although this does not directly translate to Windows internals or concepts, it is crucial to understand, as it could be leveraged to aid in abusing internals.

# Dynamic Link Libraries
A DLL is a library that contains code and data that can be used by more than one program at the same time. DLLs are used as one of the core functionalities behind application execution in Windows as the use of DLLs helps promote modularization of code, efficient memory usage, and reduced disk space. So, the operating system and the programs load faster, run faster and take less disk space on the computer.
When a DLL is loaded as a function in a program, the DLL is assigned as a dependency. Since a program is dependent on a DLL, we can target the DLLs rather than the applciations to control some aspect of execution or functionality
- DLL Hijacking ([T1574.001](https://attack.mitre.org/techniques/T1574/001/))
- DLL Side-Loading ([T1574.002](https://attack.mitre.org/techniques/T1574/002/))
- DLL Injection ([T1055.001](https://attack.mitre.org/techniques/T1055/001/))

---

DLLs are created no different than any other application, as they only require slight syntax modifications to work. Bellow is an example of a DLL
```cpp
#include "stdafx.h"
#define EXPORTING_DLL
#include "sampleDLL.h"
BOOL APIENTRY DllMain( HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	return TRUE;
}

void HelloWorld()
{
	MessageBox( NULL, TEXT("Hello World"), TEXT("In a DLL"), MB_OK);
}
```
Below is the header file for the DLL, it will define what functions are imported and exported.
```cpp
#ifndef INDLL_H
	#define INDLL_H
	#ifdef EXPORTING_DLL
		extern __declspec(dllexport) void HelloWorld();
	#else
		extern __declspec(dllimport) void HelloWorld();
	#endif
#endif
```
Once the DLL has been created, it can be loaded in a program using **load-time dynamic linking** or **run-time dynamic linking**.
When loaded using **load-time dynamic linking**, explicit calls to the DLL functions are made from the application. We can only achieve this type of linking by proving a header (`.h`) and import library (`.lib`) file. Below is an example of calling an exported DLL function from an application.
```cpp
#include "stdafx.h"
#include "sampleDLL.h"
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    HelloWorld();
    return 0;
}
```
When loaded using **run-time dynamic linking** a separate function (`LoadLibrary` or `LoadLibraryEx`) is used to load the DLL at run time. Once loaded, we need to use `GetProcAddress` to identify the exported DLL function to call. Bellow is an example of loading and importing a DLL function in an application.
```cpp
...
typedef VOID (*DLLPROC) (LPTSTR);
...
HINSTANCE hinstDLL;
DLLPROC HelloWorld;
BOOL fFreeDLL;

hinstDLL = LoadLibrary("sampleDLL.dll");
if (hinstDLL != NULL)
{
    HelloWorld = (DLLPROC) GetProcAddress(hinstDLL, "HelloWorld");
    if (HelloWorld != NULL)
        (HelloWorld);
    fFreeDLL = FreeLibrary(hinstDLL);
}
...
```
In malicious code, we will be often using run-time dynamic linking rather than the load-time one. This is because a malicious program may need to transfer files between memory regions, and transferring a single DLL is more manageable than importing using other file requirements.

# Portable Executable Format

Executables and applications are a large portion of how Windows internals operate at higher level. The Portable Executable (PE) format defines the information about the executable and stored data. The PE format also defines the structure of how data components are stored.
The PE format is an overarching structure for executable and object files. The PE and COFF (Common Object File Format) files make up the PE format.
PE data is most commonly seen in the **hex dump** of an executable file. Below will be a break down of a hex dump of calc.exe into the sections of PE data. This structure of data is broken up into seven components.
![[Pasted image 20240812044240.png]]

---

The **DOS Header** defines the type of file. 
The `MZ` DOS header defines the file format as `.exe`. 
```
Offset(h) 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
00000000  4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00  MZ..........ÿÿ..
00000010  B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00  ¸.......@.......
00000020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
00000030  00 00 00 00 00 00 00 00 00 00 00 00 E8 00 00 00  ............è...
00000040  0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68  ..º..´.Í!¸.LÍ!Th
```

The **DOS Stub** is a program run by default at the beginning of a file that prints a compatibility message. This does not affect any functionality of the file for most users. 
```
00000040  0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68  ..º..´.Í!¸.LÍ!Th
00000050  69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F  is program canno
00000060  74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20  t be run in DOS 
00000070  6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00  mode....$.......
```

The **PE File Header** defines the format of the file, contains the signature and image file header, and other information headers. This is the section with the lest human readable output. We can identify the start from the `PE` stub in the hex dump
```
000000E0  00 00 00 00 00 00 00 00 50 45 00 00 64 86 06 00  ........PE..d†..
000000F0  10 C4 40 03 00 00 00 00 00 00 00 00 F0 00 22 00  .Ä@.........ð.".
00000100  0B 02 0E 14 00 0C 00 00 00 62 00 00 00 00 00 00  .........b......
00000110  70 18 00 00 00 10 00 00 00 00 00 40 01 00 00 00  p..........@....
00000120  00 10 00 00 00 02 00 00 0A 00 00 00 0A 00 00 00  ................
00000130  0A 00 00 00 00 00 00 00 00 B0 00 00 00 04 00 00  .........°......
00000140  63 41 01 00 02 00 60 C1 00 00 08 00 00 00 00 00  cA....`Á........
00000150  00 20 00 00 00 00 00 00 00 00 10 00 00 00 00 00  . ..............
00000160  00 10 00 00 00 00 00 00 00 00 00 00 10 00 00 00  ................
00000170  00 00 00 00 00 00 00 00 94 27 00 00 A0 00 00 00  ........”'.. ...
00000180  00 50 00 00 10 47 00 00 00 40 00 00 F0 00 00 00  .P...G...@..ð...
00000190  00 00 00 00 00 00 00 00 00 A0 00 00 2C 00 00 00  ......... ..,...
000001A0  20 23 00 00 54 00 00 00 00 00 00 00 00 00 00 00   #..T...........
000001B0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
000001C0  10 20 00 00 18 01 00 00 00 00 00 00 00 00 00 00  . ..............
000001D0  28 21 00 00 40 01 00 00 00 00 00 00 00 00 00 00  (!..@...........
000001E0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
```

The **Image Optional Header** has a deceiving name and is important part of the **PE File Header**. it is only optional for object files. 

The **Data Dictionaries** are part of the image optional header. They point to the image data directory structure.

The **Section Table** will define the available sections and information in the image. These sections store the contents of the file, such as code, imports and data. We can identify each definition form the table in the hex dump
```
000001F0  2E 74 65 78 74 00 00 00 D0 0B 00 00 00 10 00 00  .text...Ð.......
00000200  00 0C 00 00 00 04 00 00 00 00 00 00 00 00 00 00  ................
00000210  00 00 00 00 20 00 00 60 2E 72 64 61 74 61 00 00  .... ..`.rdata..
00000220  76 0C 00 00 00 20 00 00 00 0E 00 00 00 10 00 00  v.... ..........
00000230  00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40  ............@..@
00000240  2E 64 61 74 61 00 00 00 B8 06 00 00 00 30 00 00  .data...¸....0..
00000250  00 02 00 00 00 1E 00 00 00 00 00 00 00 00 00 00  ................
00000260  00 00 00 00 40 00 00 C0 2E 70 64 61 74 61 00 00  ....@..À.pdata..
00000270  F0 00 00 00 00 40 00 00 00 02 00 00 00 20 00 00  ð....@....... ..
00000280  00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40  ............@..@
00000290  2E 72 73 72 63 00 00 00 10 47 00 00 00 50 00 00  .rsrc....G...P..
000002A0  00 48 00 00 00 22 00 00 00 00 00 00 00 00 00 00  .H..."..........
000002B0  00 00 00 00 40 00 00 40 2E 72 65 6C 6F 63 00 00  ....@..@.reloc..
000002C0  2C 00 00 00 00 A0 00 00 00 02 00 00 00 6A 00 00  ,.... .......j..
000002D0  00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 42  ............@..B
```
Now that the headers have defined the format and function of the file, the sections can define the contents and data of the file.

| **Section  <br>** | **Purpose**                                          |
| ----------------- | ---------------------------------------------------- |
| .text             | Contains executable code and entry point             |
| .data             | Contains initialized data (strings, variables, etc.) |
| .bss              | Contains uninitialized data                          |
| .rdata            | Contains read only data                              |
| .idata            | Contains imported objects                            |
| .edata            | Contains exportable objects                          |
| .reloc            | Contains relocation information                      |
| .rsrc             | Contains application resources (images, etc.)        |
| .debug            | Contains debug information                           |

---

We can quickly check all this information with [[Detect It Easy]], instead of just manually browsing the hex dump.

# Interacting with Windows Internals
Thankfully very accesible and researched. Probably the best way that we have to interact is to interface through Windows API calls. These provide native functionality to interact with the Windows OS. The API contains the Win32 API and, less commonly, the Win64 API. 
Most Windows internals components require interacting with physical hardware and memory. The Windows kernel will control all programs and processes and bridge all software and hardware interactions . This is especially important since many Windows internals require interaction with memory in some form.
An application by default normally cannot interact with the kernel or modify physical hardware and requires an interface. This problem is solved through the use of processor modes and access levels. A windows processor has a **user** and **kernel** mode. The processor will switch between these modes depending on access and requested mode. This switch between user mode and kernel mode is often facilitated by system and API calls. This point is sometimes referred to as the **Switching point**.

| **User mode**                                        | **Kernel Mode**                              |
| ---------------------------------------------------- | -------------------------------------------- |
| No direct hardware access                            | Direct hardware access                       |
| Creates a process in a private virtual address space | Ran in a single shared virtual address space |
| Access to "owned memory locations"                   | Access to entire physical memory             |
Applications started in user mode or **userland** will stay in that mode until a system call is made or interfaced through an API. When a system call is made, the application will switch modes.
When looking at how languages interact with the Win32 API, this process can become further warped, the application will go through the language runtime before going through the API. The most common example is C# executing through the CLR before interacting with the Win32 API and making system calls.

--- 

We will inject a message box into our local process to demonstrate a POC to interact with memory. The steps to write a message box to memory are the following
1. Allocate local process memory for the message box
2. Write/copy the message box to allocated memory
3. Execute the Message box from local process memory
At step one, we can use `OpenProcess` to obtain the handle of the specified process
```cpp
HANDLE hProcess = OpenProcess(
	PROCESS_ALL_ACCESS, // Defines access rights
	FALSE, // Target handle will not be inhereted
	DWORD(atoi(argv[1])) // Local process supplied by command-line arguments 
);
```
Then we can use `VirtualAllocEx` to allocate a region of memory with the payload buffer
```cpp
remoteBuffer = VirtualAllocEx(
	hProcess, // Opened target process
	NULL, 
	sizeof payload, // Region size of memory allocation
	(MEM_RESERVE | MEM_COMMIT), // Reserves and commits pages
	PAGE_EXECUTE_READWRITE // Enables execution and read/write access to the commited pages
);
```
Then we can use `WriteProcessMemory` to write to the allocated region of memory
```cpp
WriteProcessMemory(
	hProcess, // Opened target process
	remoteBuffer, // Allocated memory region
	payload, // Data to write
	sizeof payload, // byte size of data
	NULL
);
```
And finally, we can use `CreateRemoteThread` to execute our payload from memory
```cpp
remoteThread = CreateRemoteThread(
	hProcess, // Opened target process
	NULL, 
	0, // Default size of the stack
	(LPTHREAD_START_ROUTINE)remoteBuffer, // Pointer to the starting address of the thread
	NULL, 
	0, // Ran immediately after creation
	NULL
); 
```