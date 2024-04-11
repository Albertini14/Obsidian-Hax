[[C2#Frameworks#Armitage|Armitage]] is a GUI extension of [[Metasploit]].
There are two commands that it includes that are of interest.
```shell
sudo -E teamserver <IP address> <Password>
```
This will start the Armitage server that will allow multiple users to be able to connect to by using the IP of our Armitage server and a password to allow access.

```shell
sudo -E armitage
```
Upon executing this binary it will prompt us with some connection information (host and port) as well as a user (use the one given to you by the `teamserver`) and password. 

### Starting
Now, Armitage relies heavily on Metasploit's Database functionality, so we must start and initialize the database before launching Armitage, on new installations or when errors.
```shell
systemctl start postgresql && systemctl status postgresql postgresql.service - PostgreSQL RDBMS
```
Lastly, we must initialize the database so that Metasploit can use it
```shell
msfdb --use-defaults delete

msfdb --use-defaults init
```

Finally we can set up the `teamserver` with our IP and a password to host the Armitage server, and it will give us the details to share to our team for them to join.
If we are joining or going by ourselves running `armitage` will be enough. (we can use `127.0.0.1` as host when alone)

