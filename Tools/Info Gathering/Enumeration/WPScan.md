Is capable of enumerating and researching security vulnerability categories present in WordPress sites like:
- Sensitive Information Disclosure
- Path Discovery
- Weak Password Policies
- Presence of Default Installation
- Testing Web Application Firewalls

| Flag         | Description                                                                                           | Full Example                     |
| ------------ | ----------------------------------------------------------------------------------------------------- | -------------------------------- |
| `p`          | Enumerate Plugins                                                                                     | `--enumerate p`                  |
| `t`          | Enumerate Themes                                                                                      | `--enumerate t`                  |
| `u`          | Enumerate Usernames                                                                                   | `--enumerate -u`                 |
| `v`          | Use WPVulnDB to cross-reference for vulnerabilities. Example command looks for vulnerable plugins (p) | `--enumerate vp`                 |
| `aggressive` | This is an aggressiveness profile for WPScan to use.                                                  | `--plugins-detection aggressive` |


# Enumerating for...
## Installed Themes
WordPress stores Themes in the `/wp-content/themes` folder, so we could try to enumerate that folder in order to try to find the theme that the page uses and to see if it could be vulnerable.
We could find out the theme used by the page by using the `--enumerate` flag with the `t` argument like this:
```sh
wpscan --url http://website.com/ --enumerate t
```

## Installed Plugins
A very common feature of webservers is "Directory Listing" and is often enabled by default. Simply, it is the listing of files in the directory that we are navigating to (similar to the `ls` command). "Directory Listing" occurs when there is no file present that the webserver has been told to process. A very common file is "index.html" and "index.php". As these files aren't present in the web directory, the contents of the directory are displayed instead.

Now, WPScan can do this type of enumeration in the `/wp-content/plugin/` folder as here is where they all be located. And once it founds one it will give us as well the version and we can search for vulnerabilities that that plugin may introduce.
```sh
wpscan --url http://website.com/ --enumerate p
```
## Users
WordPress sites authors for posts. Authors are in fact a type of user. We can search for these with the `u` argument
```sh
wpscan --url http://website.com/ --enumerate u
```
## Vulnerable things
In the previous commands, we have the need to look at the output and use sites such as  [MITRE](), [NVD]() and [CVEDetails]() to look up the names of these plugins and the version numbers to determine any vulnerabilities.
WPScan has the `v` argument that can be prepended to other arguments to output the the vulnerabilities. (this requires setting up WPScan to use the WPVulnDB API)
```sh
wpscan --url http://website.com/ --enumerate vp
```
# Password Attack
After determining a list of possible usernames que can use W{Scan to perform a brute forcing technique against the username we specify and a password list that we provide
```sh
wpscan --url http://website.com/ --passwords rockyou.txt --usernames user
```

# Stealth
Unless specified, WPScan will try to be as least noisy as possible. This means that some plugins and themes may be missed by our WPScan. So, we can use arguments like `--plugins-detection` and an aggressiveness profile (`passive/aggressive`) to specify this
```sh
wpscan --url http://website.com/ -e p --plugins-detection aggressive
```

