Basic syntax
```sh
john [options] [file]
```
# Automatic Cracking
John has built-in features to detect what type of hash its been given, and to select the appropriate rules and formats to crack it. Although good it can be unreliable. To use it we simply do not specify which type of hash we gave to him. 
ex
```sh
john --wordlist=rockyou.txt file2crack.txt
```
# Format Specific Cracking
First we have to [[Hashes#Identifying Hashes|identify the hash]]. Once done this, we can tell john to use it while cracking the provided hash 
```sh
john --format=[format] file2crack.txt
```
For a list of all John's formats we use
```sh
john --list=formats
```
In some cases if we are dealing with a standard hash type we may need to prefix it with `raw-` to tell john that we are dealing with a std hash type.


# Single Crack mode
In this mode, John uses only the information provided in the username, to try and work out possible passwords from other data, by slightly changing the letters and numbers contained within the username.

## Word Mangling
If we take a username John, some possible passwords could be:
- John1, John2, John3, etc.
- John, JOhn, JOHn, etc.
- John!, John$, John&, etc.
Here John is building its own dictionary based on the information that it has been fed and uses a set of rules called "mangling rules" which define how it can mutate the word it started with to generate a wordlist based off of relevant factors for the target we are trying to crack. This is exploiting how poor passwords can be based off of information about the username or the service they're logging into.

## GECOS
John implementation of word mangling features compatibility with the Gecos fields of the UNIX operating system such as Linux. In both `/etc/shadow` and `/etc/passwd`, in each line, every field is separated by ":". Each one of the fields that these records are split into are called Gecos fields. John is able to take information stored in those records such as full name, and home directory name to add in to the wordlist it generates when cracking `/etc/shadow` hashes in single crack mode

## Using it
```sh
john --single FILE
```
its important to remember that if we are using single crack mode we need to change the file format that we are feeding john for it to understand what data to create a wordlist from. We can do this by prepending the hash with the username that the hash belongs to, like so:
```sh
from:
7bf6d9bb82bed1302f331fc6b816aada
to:
joker:7bf6d9bb82bed1302f331fc6b816aada
```

## Custom Rules
Many organizations will require a certain level of passwords complexity to try and combat dictionary attacks, meaning that if we create an account somewhere, we can learn about the rules that they have for passwords. These rules can be something like:
- Your password must have at least one upper case letter
- Your password must contain at least one number
- Your password must contain at least one symbol
Following this rules, a certain pattern appears that some users tend to follow and that pattern often results in passwords like the following:
$$Password1!$$
A password with the capital letter first, and a number followed by a symbol at the end. 
Although this in fact meets the password complexity requirements we can exploit the fact that we know the likely position of these added elements to create dynamic passwords from our wordlists.

### Creating Custom Rules
Custom rules are defined in the `john.conf` file, usually located in `/etc/john/john.conf`
For a full look into a the rules check [wiki](https://www.openwall.com/john/doc/RULES.shtml). But assuming the above password were to be our target, we can create the following.

The first line:
`[List.Rules:NoobieRules]` - is used to define the name of our rule, this is what we will use to call our custom rule as a John argument.

We then use a regex style pattern match to define where in the word will be modified

`Az`- Takes the word and appends it with the characters we define
`A0`- Takes the word and prepends it with the characters we define
`c`- Capitalises the character positionally

These can be used in combination to define where and what in the word we want to modify

Lastly, we then need to define what characters should be appended, prepended or otherwise included, we do this by adding character sets in `[]` in the order they should be used. These directly follow the modifier patterns inside of `" "`. Some of the most common are:
- `[0-9]`- Will include numbers 0-9
- `[0]`- Will include only the number 0
- `[A-z]`- Will include both upper and lowercase
- `[A-Z]`- Will include only uppercase letters
- `[a-z]`- Will include only lowercase letters
- `[a]`- Will include only a
- `[!@#$%]`- will include the symbols !@#$%

Adding all of this, in order to generate a wordlist from the rules that would match the example password 'Johnny1!' (assuming johnny was in our wordlist) our entry would look like this
```sh
[List.Rules:BasicPass]
cAz"[0-9][!@#$%^&*]
```
Making it so
- Capitalize the first letter `c`
- Append to the end of the word `Az`
- A number `[0-9]`
- Followed by a symbol `[!@#$%^&*]`

### Using Custom Rules
We could then call this custom rule as a john arg like this
```sh
john --wordlist=[wordlist] --rule=BasicPass [file]
```

# Cracking Password Protected Zip File
Similarly to the [[Unshadow]] tool, we are going to convert the zip file into a hash format that John is able to understand, and hopefully crack. The basic usage is like
```
zip2john [options] [zip file] > zip.txt
```
And then we can give john the outputted file
```sh
john zip.txt
```

# Cracking Password Protected RAR files
Similarly to zips we can use 
```sh
rar2john [rar file] > [output file].txt
```
and feed it into john.

# Cracking SSH Key Passwords
Using John to crack the SSH private key password of id_rsa files. Unless configured otherwise, you authenticate your SSH login using a password. However, you can configure key-based authentication, which lets you use your private key, id_rsa, as an authentication key to login to a remote machine over SSH. However, doing so will often require a password- here we will be using John to crack this password to allow authentication over SSH using the key.
Like the other cases we can use the following
```sh
ssh2john [id_rsa private key file] > output.txt

john output.txt
```

# Other File Formats
There are a lot of other file formats for which john can convert and crack the hash. For a full list see [repository](https://github.com/openwall/john/tree/bleeding-jumbo/run) or `/usr/share/john` in kali