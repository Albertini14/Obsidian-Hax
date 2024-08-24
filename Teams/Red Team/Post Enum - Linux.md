# System
We can get more information about the **linux distribution and release version** by searching for files that end with `-release` in `/etc/`, using 
```Bash
ls /etc/*-release
```
can help us to find these files. 

We can also use find the **system name** using 
```bash
hostname
```

Various files on a system can provide plenty of useful information, particularly those following `/etc/passwd`, `/etc/group`, and `/etc/shadow`. 

To find **installed application** we can list the files in `/usr/bin` and `/sbin/`

On a **RPM-based linux system**, we can get a list of all installed packages using 
```bash
rpm -qa
```
which indicates to query all packages

On a **Debian-based system**, we can get a list of all installed packages using
```bash
dpkg -l
```

# Users
One of the main ways to gather usernames is `/etc/passwd`, however, there are other ways in which we can gain insight about other users.

We can show who is logged in using 
```bash
who
```
This will display not only which users are connected, but also which are **logged directly** and which are **connected over the network**, as well as their **IP addresses** in the latter case.

To increase our info, we can use
```bash
w
```
Which shows not only **who is logged in**, but also **what they are doing**

To print the real and effective **user and group ID**, we can issue the command `id`

We can also display a listing of the last logged-in users, as well as who logged out and how much they stayed connected with
```bash
last
```

# Networking
The IP addresses can be shown using `ip address show` (which can be shortened to `ip a s`) or with the older version `ifconfig -a`. This shows  the network interface (like `eth0`), as well as the IP address and subnet mask.

The DNS servers can be found in the `/etc/resolv.conf`, from this we can see which DNS correspond to which IP addresses

`netstat` is a useful command for learning about the network connections, routing tables, and interface statistics. 

| Option | Description                                                             |
| ------ | ----------------------------------------------------------------------- |
| `-a`   | show both listening and non-listening sockets                           |
| `-l`   | show only listening sockets                                             |
| `-n`   | show numeric output instead of resolving the IP address and port number |
| `-t`   | TCP                                                                     |
| `-u`   | UDP                                                                     |
| `-x`   | UNIX                                                                    |
| `-p`   | Show the PID and name of the program to which the socket belongs        |
We can use any combination that suits our needs, for instance, `netstat -plt` will return programs that are listening on TCP sockets. Or `netstat -atupn` which will list all TCP and UDP listening and established connections and the program names with addresses and ports in numeric format, similar to what `nmap` would give us if we probed the machine from the outside, however more reliable as we now have certainty that we didn't miss one.

`lsof` stands for List of Open Files. If we want to display only internet and network connections, we can use `lsof -i`. With this we can see if a user is connected to any other server from the machine over any port. To get a complete list of matching programs we need to run it as `root`.
Because this list can get lengthy, we can further the output by specifying the ports we are interested in, by appending `:PORT` to the end like `lsof -i :22` to only display those related to port 22.
We can also use `sudo lsof -i -P -n` to display all network connections, and not resolve the IP address as well as the ports, to instead use the numeric values, this allows us to `grep` the results in the search for specific ports/IPs


# Running Services
Getting a snapshot of the running processes can provide many insights. `ps` lets us discover running processes and plenty of information about them. 
We can list every process on the system using `ps -e`, we can also use the `-l` or `-f` flags to increase the info we get from each, like start time and user that created that process.

| Option | Description         |
| ------ | ------------------- |
| `-e`   | all processes       |
| `-f`   | full-format listing |
| `-j`   | jobs format         |
| `-l`   | long format         |
| `-u`   | user-oriented format |
We can also get processes using BSD syntax: `ps ax` or `ps aux`. In here `a` and `x` lift the restrictions of "only yourself" and "must have tty", allowing us to display all processes, while the `u` is for details about the user that has the process.
For a more "visual" output, we can issue `ps axjf` to print a process tree, creating ASCII art with the process hierarchy. 
 We can also of course `grep` our results to search for certain things like users, programs, times, etc.
 