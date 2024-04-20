# Profiling
Catering to a good wordlist is critical to carry out a good password attack, so we can take advantage of different techniques and tools to help us create both username and password lists
## Default Passwords
As the name says, some services offer default passwords/credentials, so checking them out first is always worth
- [cirt.net/passwords](https://cirt.net/passwords)
- [default-password.info/](https://default-password.info/)
- [datarecovery.com](https://datarecovery.com/rd/default-passwords/)

## Weak Passwords
Generated mostly by both leaks and by experienced from professionals, we can use these lists to help us
- [skullsecurity](https://wiki.skullsecurity.org/index.php?title=Passwords)- This includes the most well-known collections of passwords.
- [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Passwords) - A huge collection of all kinds of lists, not only for password cracking.

## Leaked Passwords
Password and data dumps can be useful to try look at real passwords and create a list from there or to even match certain emails or usernames to other information
- [SecLists/Passwords/Leaked-Databases](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Leaked-Databases)
- [haveibeenpwned](https://haveibeenpwned.com) - Although not a leak, we can search if a certain email has been leaked and maybe find information in that leak 
## Combining Lists
Once we have selected our lists we can go ahead and combine them
```shell
cat file1.txt file2.txt file3.txt> combined.txt
sort combined.txt | uniq -u > cleaned.txt
```
## Customized Lists
Often a company's website contains valuable information about the company and its employees, including emails and employee names. In addition, it may contain keywords specific to what the company offers, including products and service names, which may be used in an employee's password.
We can use [[CeWL]] to crawl the website and extract strings or keywords. 
```shell
cew; http://company.com -d 5 -m 5 -w list.txt
```
## Username Wordlists
Gathering employees' names is essential, we can generate username lists from the target's website by following certain patterns and behaviors, that some companies or people may use. One example will be following the next structure
- **{first name}:**` john`
- **{last name}:** `smith`
- **{first name}{last name}:  `johnsmith`** 
- **{last name}{first name}:  `smithjohn`**  
- first letter of the **{first name}{last name}: `jsmith` 
- first letter of the **{last name}{first name}: `sjohn` 
- first letter of the **{first name}.{last name}:` j.smith`** 
- first letter of the **{first name}-{last name}:` j-smith`** 
- and so on
We can use a tool [username_generator](https://github.com/therodri2/username_generator.git) that could help create a list with most of the possible combinations
```shell
git clone https://github.com/therodri2/username_generator.git
cd username_generator
python3 username_generator.py -h
```
We can simply feed it a list of `Name LastName` and it will generate our combinations

##  Keyspace Technique
In this technique, we specify a range of characters, numbers, and symbols in our wordlist to create all posible combinations. With [[Crunch]] we can specify some options that will help us do this
```
crunch MIN_LEN MAX_LEN CHARACTERS -o WORDLIST.txt
```
We could use this as either a wordlist on its own, or we could use it to append it to other wordlists

## CUPP
Common User Passwords Profiler, is an automatic and interactive tool written in Python for creating custom wordlists. For example, if we know some details about the target such as birthdate, pet name, company name, etc., we could use this to generate passwords based on this information. CUPP will take the information supplied and generate a custom wordlists based on what's provided. It also offers support for 1337 speak
```shell
git clone https://github.com/Mebus/cupp.git
cd cupp
python3 cupp.py --help
```
We can use the interactive mode, where it asks us questions about the target and based on the provided answers it creates a custom wordlist
```shell
python3 cupp.py -i
```

# Attacks
## Offline
### Dictionary Attacks
This is a technique used to guess passwords by using well-known words or phrases. The dictionary attacks relies entirely on pre-gathered wordlists that were previously generated or found. It is important to choose or create the best candidate wordlist for our target in order to succeed in this attack.
Here we can use [[Hashcat]] or [[John The Ripper]] to crack hashes.
### Brute Force
Now, instead of trying just a list of words like a civilized human, we can go ahead and start trying for all posible combinations. We can do this with Hashcat with the use of charsets and `-a 3`. 
### Rule-Based attacks
Also known as hybrid attacks. Rule-Based attacks assume the attacker knows something about the password policy. Rules are applied to create passwords within the guidelines of the given password policy and should, in theory, only generate valid passwords. Using pre existing wordlists maye be useful when generating passwords that fit a policy, for example by mangling them.

Again, we can use either [[Hashcat]] or [[John The Ripper]] here. For example we could check the already existing rules for John with the following
```shell
cat /etc/john/john.conf|grep "List.Rules:" | cut -d"." -f3 | cut -d":" -f2 | cut -d"]" -f1 | awk NF
```
Then we could use one of these rules to create a new list, or to directly crack a hash
```shell
john --wordlist=dict.txt --rules=best64 --stdout > newlist.txt 
```

## Online
Online password attacks involve guessing passwords for networked services that use a username and password authentication scheme, including services such as HTTP, SSH, VNC, FTP, SNMP, POP3, etc. For this [[Hydra]] is a really good tool. 
But other tools like [[Medusa]] or [[Ncrack]] can also serve.
### Password Spraying
Is a technique used to identify valid credentials. It is one of the common password attacks for discovering weak credentials. Whilst a brute-force attack targets a specific username to try many weak and predictable passwords, password spraying attacks target many usernames using one common weak password which could help avoid lockout policy.
Common and weak passwords often follow a pattern and format, things like, 
- The current season followed by the year
- The name of the company followed by some numbers
- The current month and year
If password complexity is enforced, then a password that meets such requirements like `Company2024!`. To be successful in the password spraying we need to enumerate the target and create a list of valid usernames (or email addresses list)

### [[Network Services Vulnerabilities#FTP|FTP]]
Here we can use a basic hydra command, just by specifying user and password, that we may have gathered from a previous enumeration phase
```shell
hydra IP ftp -l ftp -P passlist.txt -t 16 -f -v
```
### [[Network Services Vulnerabilities#SMTP|SMTP]]
Likewise, a similar command, just changing a user for an email
```shell
hydra IP smtp -l email@company.com -P wordlist.txt -t 16 -f -v
```
### HTTP login pages
To do this, we are going to use Hydra to specify a type of HTTP request, whether `GET` or `POST`. Checking hydra options: `hydra http-get-form -U`, we can see that hydra has the following syntax for the get form
`<url>:<form parameters>[:<optional>[:<optional>]:<condition string>`


