A Linux alternative to enum.exe for enumerating data from Windows and Samba hosts.

Enum4linux is a tool for enumerating information from Windows and Samba systems. It attempts to offer similar functionality to enum.exe formerly available from [bindview](http://www.bindview.com/).

It is written in Perl and is basically a wrapper around the Samba tools smbclient, rpclient, net and nmblookup.

| Option | Function                  |
| ------ | ------------------------- |
| `-U`   | Get userlist              |
| `-M`   | get machine list          |
| `-N`   | get namelist dump         |
| `-S`   | get sharelist             |
| `-P`   | get password policy info  |
| `-G`   | get group and member list |
| `-a`   | all of the above          |
```Shell
enum4linux [options] IP
```