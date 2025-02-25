`ssh USER@IP` - Secure Shell, network protocol to connect with other machines

`su USERNAME` - change user while logged as another / -l USERNAME logs in as user inheriting more properties

`whoami` - Tells you who you are
`ls` - lists files in current directory 
	`-a` shows all files, including hidden ones 
	`-l` shows information about who can read, write and execute the file
	![[Pasted image 20231019140816.png]]

`cat FILENAME` - concatenates (prints) the contents of any text file

`cd` - Change directory / cd .. - go up by one directory

`pwd` - print working directory

`wc` - Wordcount / -l for lines / -w words / -m characters

`man COMMAND` - consult the documentation of a command
	We can also use `--help` at the end of most commands to display more information about that command, but man is certain to work

`find`
	`-name NAME.extension`
		can also use an * instead of the name as a wildcard displaying every of the entered extension

`grep [options] PATTERNS [file]`
	Searches for a string and returns all of the lines that contain that string (caps matter), we can use flags to specify certain pattern or to ignore caps, etc. 

`touch NAME` - creates a blank file in the current directory

`mkdir NAME` - creates a new directory

`cp FILE1 FILE2` - copies the data of the first file to the second

`mv FILE1 [FILE2|PATH]` - moves the entire file 1 to the second file, can also be used for renaming

`rm NAME` - removes a file
	`-R NAME` removes a directory 

`file NAME` - returns the type of the file

`nano FILENAME` - creates or edits a file, more advanced text editor Ctrl + X to exit

`vim` - even more advanced file editor

`curl  URL [OPTIONS]` - downloads or uploads files from the specified URL, supports HTTP, HTTPS, FTP, FTPS, SCP, SFTP 
	`-d` data to be sent
	`-H` add additional header to the request, in case of form data 'Content-Type: application/x-www-form-urlencoded'
	`-X` GET,POST,etc request
	`--cookie "Name=Value"`

`wget http://...` - downloads files from the specified http path, supports HTTP and FTP

`scp FILE USER@IP:PATH` | `scp USER@IP:PATH FILE`
	secure copy  is a way to copy files through the SSH protocol, similar to the cp command this creates a copy of the first file to the specified path, taking the user we wished to be logged in as to the specified ip and path from which to take or put the file

`python3 -m http.server` - this command turns the computer into a quick server from which other computers can then, by using curl and wget download your files, this http server will serve the files in the directory that you run the command

`ps` - shows the running processes 
	`ps aux` - show the processes run by other users

`top` - shows the processes in a real time manner refreshing every 10 seconds

`kill PID` - kills a process with its respective process ID
	`SIGTERM` - kills the process but allows it to do some cleanup beforehand
	`SIGKILL` - kills it without any cleanup
	`SIGSTOP` - stops/suspends it

`systemctl [OPTION]  [SERVICE]` -  this command allows us to interact with the systemd process, for example allowing us to start certain processes (systemctl start apache2) 

`fg PID` - foregrounds a process, taking it from the background with either & or Ctrl + Z 
crontab - starts a process to schedule certain commands to execute at a certain time or every so often


### Operators
`&` - runs the command in the background allowing us to do other things while it runs

`&&` - runs multiple commands one after another, it only runs the next command if the previous was successful

`>` - it will take the output of a command and write it to a new file, creating a file if it does not exist or overwriting an already existing file (echo "hallo" > msj.txt)

`>>` - similar to the previous operator, this operator will only append the contents to the new direction, so it will not overwrite any previous data

`|` - Pipes the output of a command to another one

### Directories

`/etc` - commonplace locations to store system files used by the OS, can be the place to find the sudoers file (list of users and groups that have permission to run sudo or set of commands as root), passwd and shadow files, which store the passwords for each user in [[sha512]]

`/var` - stores data that is frequently accessed or written by services or applications running on the system, for example /var/log

`/root` - folder of the root user

`/tmp` - volatile directory that is restarted