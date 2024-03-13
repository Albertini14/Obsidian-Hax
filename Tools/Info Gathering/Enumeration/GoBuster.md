Brute-force command-line to find hidden directories and pages

| Option  | Description                                               |
| ------- | --------------------------------------------------------- |
| `dir`   | Enumerates directories                                    |
| `dns`   | Enumerates domains/subdomains                             |
| `vhost` | Enumerates virtual hosts                                  |
| `-u`    | url                                                       |
| `-w`    | Wordlist                                                  |
| `-t`    | Number of concurrent threads (default 10, recommended 64) |
| `-v`    | verbose                                                   |
| `-z`    | don't display progress                                    |
| `-q`    | don't print the banner                                    |
| `-o`    | Output file                                               |


# Dir mode
GoBuster has a dir mode that allows us to enumerate website directories. Often, directory structures of websites and web-apps follow a certain convention, making them susceptible to brute-forcing using wordlists. 
GoBuster scans and returns the status codes, letting us know if we could request those directories or not. Additionally we could search for files using other flags.

The normal command for a directory search goes as follows:
```bash
gobuster dir --url https://domain.com -w directories.txt
```

## Useful flags
| Flag | Long Flag                  | Description                                                 |
| ---- | -------------------------- | ----------------------------------------------------------- |
| `-c` | `--cookies`                | Cookies to use for requests                                 |
| `-x` | `--extensions`             | File extension(s) to search for                             |
| `-H` | `--headers`                | Specify HTTP headers, -H 'Header1: val1' -H 'Header2: val2' |
| `-k` | `--no-tls-validation`      | Skip TLS certificate verification                           |
| `-n` | `--no-status`              | Don't print status codes                                    |
| `-P` | `--password`               | Password for Basic Auth                                     |
| `-s` | `--status-codes`           | Positive status codes                                       |
| `-b` | `--status-codes-blacklist` | Negative status codes                                       |
| `-U` | `--username`               | Username for Basic Auth                                     |
A common combination of the "dir" mode is the `-x` flag, as it allows us to search for one or more file types such as .txt, .php, .conf, .js, etc.
Altering the normal syntax as follows:
```sh
gobuster dir -u [url] -w [wordlist] -x .txt,.js,.php
```
### k
The `-k` flag is a little special because during CTF or pentests, if HTTPS is being used we may encounter an invalid cert error. This can be quickly fixed by just adding this flag to bypass the invalid certification. It can also be used with "vhost" mode

# DNS mode
Just because something is patched in the regular domain, does not mean it is patched in the sub-domain. To use "dns" mode we again need to add the domain(`-d`) and wordilst options to get the standard command
```sh
gobuster dns -d domain.com -w subdomains.txt
```
This will do a sub-domain scan on the domain and report them to us.

## Useful flags
| Flag | Long Flag      | Description                                                  |
| ---- | -------------- | ------------------------------------------------------------ |
| `-c` | `--show-cname` | Show CNAME Records (cannot be used with '-i' option)         |
| `-i` | `--show-ips`   | Show IP Addresses                                            |
| `-r` | `--resolver`   | Use custom DNS server (format server.com or server.com:port) |
# Vhost
This allows GoBuster to brute-force virtual hosts. These are different websites on the same machine. In some instances, they can appear to look like sub-domains, but they are not. Virtual hosts are IP based and are running on the same server. This is not usually apparent to the end-user. On an engagement, it may be worthwhile to just run GoBuster in this mode to see if it comes up with anything.
Again, to use this mode the standard syntax goes as follows:
```sh
gobuster vhost -u https://example.com -w subdomains.txt
```
When testing for IP based vhosts, it is useful to add those domains into our list of hosts in `/etc/hosts` we could do this like this
```sh
echo "IP subdomain.webenum.thm" >> /etc/hosts
```
This will allow us to use the given DNS on our scans and to search the website on a web browser 

## Useful flags
A lot of the same flags that are useful for dir mode still apply to virtual host mode.

# Useful wordlists
As for some of the default kali lists:
- /usr/share/wordlists/dirbuster/directory-list-2.3-*.txt
- /usr/share/wordlists/dirbuster/directory-list-1.0.txt
- /usr/share/wordlists/dirb/big.txt
- /usr/share/wordlists/dirb/common.txt
- /usr/share/wordlists/dirb/small.txt
- /usr/share/wordlists/dirb/extensions_common.txt - Useful for when fuzzing for files!

In addition, [SecLists](https://github.com/danielmiessler/SecLists) also includes many useful lists