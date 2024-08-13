The Windows API provides native functionality to interact with key components of the Windows OS. This API can integrate with the Windows system, offering its range of use cases, like using the Win 32 API for offensive tool and malware development, EDR engineering, and general software applications.

# Subsystems and Hardware Interaction
Windows distinguishes hardware access by two distinct modes: **user* and **kernel mode**. These modes determine the hardware, kernel, and memory access an application or driver is permitted. API call interface between each mode, sending information to the system to be processed in kernel mode. 

| **User mode**                      | **Kernel mode**                  |
| ---------------------------------- | -------------------------------- |
| No direct hardware access          | Direct hardware access           |
| Access to "owned" memory locations | Access to entire physical memory |

# Components of the API
The Win32 API (or just the Win API), has several dependent components that are used to define the structure and organization of the API.

| **Layer**               | **Explanation**                                                                                                                                                              |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| API                     | A top-level/general term or theory used to describe any call found in the win32 API structure.                                                                               |
| Header files or imports | Defines libraries to be imported at run-time, defined by header files or library imports. Uses pointers to obtain the function address.                                      |
| Core DLLs               | A group of four DLLs that define call structures. (KERNEL32, USER32, and ADVAPI32). These DLLs define kernel and user services that are not contained in a single subsystem. |
| Supplemental DLLs       | Other DLLs defined as part of the Windows API. Controls separate subsystems of the Windows OS. ~36 other defined DLLs. (NTDLL, COM, FVEAPI, etc.)                            |
| Call Structures         | Defines the API call itself and parameters of the call.                                                                                                                      |
| API Calls               | The API call used within a program, with function addresses obtained from pointers.                                                                                          |
| In/Out Parameters       | The parameter values that are defined by the call structures.                                                                                                                |

# OS Libraries
Each API call of the Win32 library resides in memory and requires a pointer to a memory address. The process of obtaining pointers to these functions is obscured because of **Address Space Layout Randomization** (ASLR) implementations. Each language or package has a unique procedure to overcome ASLR. Two of the most popular are the following
## Windows Header File
Microsoft has released the Windows header file, also knows as the Windows loader, as a direct solution to the problems associated with ASLR's implementation. Keeping the concept at a high level, at runtime, the loader will determine what calls are being made and create a thunk table to obtain function addresses or pointers. 
Once the `windows.h` file is included at the top of an unmanaged program, any Win32 function can be called

### Implementation
Low level programming languages such as C and C++ are provided with a pre-configured set of libraries that we can use to access needed API calls. The `windows.h` header file, is used to define call structures and obtain function pointers. To include the windows header, we need to prepend the line below to any C or C++ program.

```c
#include <windwos.h>
```
Now, jumping into creating an API call. For this we are going to create a pop-up window using `CreateWindowExA`.  The I/O parameters of the call look like this
```c
HWND CreateWindowExA(
  [in]           DWORD     dwExStyle, // Optional windows styles
  [in, optional] LPCSTR    lpClassName, // Windows class
  [in, optional] LPCSTR    lpWindowName, // Windows text
  [in]           DWORD     dwStyle, // Windows style
  [in]           int       X, // X position
  [in]           int       Y, // Y position
  [in]           int       nWidth, // Width size
  [in]           int       nHeight, // Height size
  [in, optional] HWND      hWndParent, // Parent windows
  [in, optional] HMENU     hMenu, // Menu
  [in, optional] HINSTANCE hInstance, // Instance handle
  [in, optional] LPVOID    lpParam // Additional application data
);
```
Now, we can take these parameters to create a call to `CreateWindwosExA`
```c
HWND hwnd = CreateWindowsEx(
	0, 
	CLASS_NAME, 
	L"Hello World!", 
	WS_OVERLAPPEDWINDOW, 
	CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, 
	NULL, 
	NULL, 
	hInstance, 
	NULL
	);
```
Once we've defined our first API call, we can implement it into an application and use the functionality of the API call. Below is an example application that uses the APU to create a small blank window.
```c
BOOL Create(
        PCWSTR lpWindowName,
        DWORD dwStyle,
        DWORD dwExStyle = 0,
        int x = CW_USEDEFAULT,
        int y = CW_USEDEFAULT,
        int nWidth = CW_USEDEFAULT,
        int nHeight = CW_USEDEFAULT,
        HWND hWndParent = 0,
        HMENU hMenu = 0
        )
    {
        WNDCLASS wc = {0};

        wc.lpfnWndProc   = DERIVED_TYPE::WindowProc;
        wc.hInstance     = GetModuleHandle(NULL);
        wc.lpszClassName = ClassName();

        RegisterClass(&wc);

        m_hwnd = CreateWindowEx(
            dwExStyle, ClassName(), lpWindowName, dwStyle, x, y,
            nWidth, nHeight, hWndParent, hMenu, GetModuleHandle(NULL), this
            );

        return (m_hwnd ? TRUE : FALSE);
    }
```
If everything went ok, we should see a window with the title "Hello World!"

## P/Invoke
Platform invoke provides tools to handle the entire process of invoking an unmanaged function from managed code, meaning, we can call the Win32 API. It will start by importing the desired DLL that contains the unmanaged function or Win API call. 
```csharp
using System;
using System.Runtime.InteropServices;

public class Program
{
[DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
...
} 
```
In here we are importing the DLL `user32` using the attribute `DLLImport`.
Note that this is not the end of the line as the function is not complete, for we must define a managed method as an external one. The `extern` keyword will inform the runtime of the specific DLL that was previously imported.
```csharp
using System;
using System.Runtime.InteropServices;

public class Program
{
...
private static extern int MessageBox(IntPtr hWnd, string lpText, string lpCaption, uint uType);
} 
```
Now we can invoke the function as a managed method, but we are calling the unmanaged function.

### Implementation
Here we have one example of how P/Invoke is implemented, we will dissect it now.
```C#
class Win32 {
	[DllImport("kernel32")]
	public static extern IntPtr GetComputerNameA(StringBuilder lpBuffer, ref uint lpnSize);
}
```
The class function stores defined API calls and a definition to reference in all future methods.
The library in which the API call structure is stored must now be imported using `DllImport`. The imported DLLs act similar to the header packages but require that we import a specific DLL with the API call we are looking for. We can reference the [API index](https://docs.microsoft.com/en-us/windows/win32/apiindex/windows-api-list) or [pinvoke.net](http://pinvoke.net/) to determine where a particular API call is located in a DLL.
From the DLL import, we can create a new pointer to the API call we want to use, notably defined by `intPtr`. Unlike other low-level languages, we must specify the I/O parameter structure in the pointer. Like in the previous method, we can find this in the Windows documentation.
Now we can implement the defined API call into an application and use its functionality. Below is an example application that uses the API to get the computer name and other information of the device it is run on.
```C#
class Win32 {
	[DllImport("kernel32")]
	public static extern IntPtr GetComputerNameA(StringBuilder lpBuffer, ref uint lpnSize);
}

static void Main(string[] args) {
	bool success;
	StringBuilder name = new StringBuilder(260);
	uint size = 260;
	success = GetComputerNameA(name, ref size);
	Console.WriteLine(name.ToString());
}
```
If successful, the program should return the computer name of the current device. 

---

Now that we've done it in .NET, we can try to adapt it to work in Powershell
Defining the API call is almost identical to .NET's implementation, but we will need to create a method instead of a class and add a few additional operators.
```powershell
$MethodDefinition = @"
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
"@;
```
The calls are now defined, but Powershell requires one further step before they can be initialized. We must create a new type for the pointer of each Win32 DLL within the method definition. The function `Add-Type` will drop a temporary file in the `/temp` directory and compile needed functions using `csc.exe`. Below is an example of the function being used
```powershell
$Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name 'Kernel32' -NameSpace 'Win32' -PassThru;
```
We can now use the required API calls with the syntax below.
```powershell
[Win32.Kernel32]::<Imported Call>()
```


# API call structure
API calls are the second main component of the Win32 library. These calls offer extensibility and flexibility that can be used to meed a plethora of use cases. API call functionality can be extended by modifying the naming scheme and appending a representational character. Microsoft supports the following for its naming scheme

| **Character** | **Explanation**                                                      |
| ------------- | -------------------------------------------------------------------- |
| A             | Represents an 8-bit character set with ANSI encoding                 |
| W             | Represents a Unicode encoding                                        |
| Ex            | Provides extended functionality or in/out parameters to the API call |
For more info [docs](https://docs.microsoft.com/en-us/windows/win32/learnwin32/working-with-strings)

---

Each API call also has a pre-defined structure to define its I/O parameters. We can find most of these structures on the corresponding API call document page of the [documentation](https://docs.microsoft.com/en-us/windows/win32/apiindex/windows-api-list), along with explanations of each I/O parameter.
Looking at the `WriteProcessMemory` API call as an example. 
```cpp
BOOL WriteProcessMemory(
  [in]  HANDLE  hProcess,
  [in]  LPVOID  lpBaseAddress,
  [in]  LPCVOID lpBuffer,
  [in]  SIZE_T  nSize,
  [out] SIZE_T  *lpNumberOfBytesWritten
);
```
For each I/O parameter, Microsoft also explains its use, expected input or output, and accepted values. Even with an explanation determining these values can sometimes be challenging for particular calls. So its always good researching and finding examples of APU call usage before using a call in our code.

# Commonly abused calls
Several API calls within the Win32 library lend themselves to be easily leveraged for malicious activity. 
Several entities have attempted to document and organize all available API calls with malicious vectors, including [SANs](https://www.sans.org/white-papers/33649/) and [MalAPI.io](http://malapi.io/).
Here are some of the most commonly abused API.

| **API Call**       | **Explanation**                                                                                                      |
| ------------------ | -------------------------------------------------------------------------------------------------------------------- |
| LoadLibraryA       | Maps a specified DLL into the address space of the calling process                                                   |
| GetUserNameA       | Retrieves the name of the user associated with the current thread                                                    |
| GetComputerNameA   | Retrieves a NetBIOS or DNS  name of the local computer                                                               |
| GetVersionExA      | Obtains information about the version of the operating system currently running                                      |
| GetModuleFileNameA | Retrieves the fully qualified path for the file of the specified module and process                                  |
| GetStartupInfoA    | Retrieves contents of STARTUPINFO structure (window station, desktop, standard handles, and appearance of a process) |
| GetModuleHandle    | Returns a module handle for the specified module if mapped into the calling process's address space                  |
| GetProcAddress     | Returns the address of a specified exported DLL  function                                                            |
| VirtualProtect     | Changes the protection on a region of memory in the virtual address space of the calling process                     |

