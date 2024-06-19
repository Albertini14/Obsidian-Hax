Nikto is capable of performing an assessment on all types of webservers. It can be used to discover possible vulnerabilities including:
- Sensitive files
- Outdated servers and programs
- Common server and software misconfigurations (Directory indexing, cgi scripts, XSS)

# Scanning
## Basic
The most basic scan can be performed by using the -`h` flag and providing an IP address or domain name as an argument. This scan type will retrieve the headers advertised by the webserver or application (Apache2, Apache Tomcat, Jenkins, etc.) and will look for any sensitive files or directories (`login.php`, `/admin/`, etc.)
```sh
nikto -h website.com
```

## Multiple Hosts
Nikto is extensive in the sense that we can provide multiple arguments in a way similar to [[Nmap]]. In fact we can take input directly from an Nmap scan to scan a host range. By scanning a subnet, we can look for hosts across an entire network range. We must instruct Nmap to output a scan into a format that is friendly using the `-oG` flag.
For example we could scan the ip 192.16.0.0/24 (subnet mask 255.255.255.0 resulting in 254 possible hosts.) with Nmap, and pipe the output to Nikto
```sh
nmap -p80 192.16.0.0/24 -oG - | nikto -h -
```
Although there are not many circumstances where we would use this, one could be when we just gained access to a network.

## Multiple Ports
A much more common scenario will be scanning multiple ports on one host. We can do this by using the `-p` flag and providing a list of port numbers delimited by a comma
```sh
nikto -h 10.10.14.06 -p 80,8080,443
```

## Verbosing
We can increase the verbosity the scans by providing the following arguments with the `-Display [arg]` flag. Unless specified, the output given by Nikto is not the entire output.

| Argument | Description                                          | Reasons for Use                                                                                                                                                                                                         |
| -------- | ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `1`      | Show any redirects that are given by the web server. | Web servers may want to relocate us to a specific file or directory, so we will need to adjust our scan accordingly for this.                                                                                           |
| `2`      | Show any cookies received                            | Applications often use cookies as a means of storing data. For example, web servers use sessions, where e-commerce sites may store products in your basket as these cookies. Credentials can also be stored in cookies. |
| `E`      | Output any errors                                    | This will be useful for debugging if your scan is not returning the results that you expect!                                                                                                                            |

## Plugins
Plugins further extend the capabilities of Nikto. Using information gathered from our basic scans, we can pick and choose plugins that are appropriate to our target. We can use `--list-plugins` to display available plugins.
Some interesting ones:

| Plugin Name     | Description                                                                                                                                                                           |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `apacheusers`   | Attempt to enumerate Apache HTTP Authentication Users                                                                                                                                 |
| `cgi`           | Look for CGI scripts that we may be able to exploit                                                                                                                                   |
| `robots`        | Analyse the robots.txt file which dictates what files/folders we are able to navigate to                                                                                              |
| `dir_traversal` | Attempt to use a directory traversal attack (i.e. LFI) to look for system files such as /etc/passwd on Linux (http://ip_address/application.php?view=../../../../../../../etc/passwd) |
We can specify the plugin we wish to use by using the `-Plugin` argument and the name of the plugin like 
```sh
nikto -h website.com -Plugin apacheuser
```

## Tuning
Nikto has several categories of vulnerabilities that we can specify our scan to enumerate and test for. The following are some of the most commonly used ones. We can use the `-Tuning [arg]` to use them

| Category Name                     | Description                                                                                                                                                        | Tuning Option |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------- |
| File Upload                       | Search for anything on the web server that may permit us to upload a file. This could be used to upload a reverse shell for an application to execute.             | 0             |
| Misconfigurations / Default Files | Search for common files that are sensitive (and shouldn't be accessible such as configuration files) on the web server.                                            | 2             |
| Information Disclosure            | Gather information about the web server or application (i.e. verison numbers, HTTP headers, or any information that may be useful to leverage in our attack later) | 3             |
| Injection                         | Search for possible locations in which we can perform some kind of injection attack such as XSS or HTML                                                            | 4             |
| Command Execution                 | Search for anything that permits us to execute OS commands (such as to spawn a shell)                                                                              | 8             |
| SQL Injection                     | Look for applications that have URL parameters that are vulnerable to SQL Injection                                                                                | 9             |
```sh
nikto -h website.com -Tuning 9 
```

## Output
To save the output we have two options .txt files or a HTML report. For this we can use the `-o` flag and provide a filename with a compatible extension to create such file.
```sh
nikto -h http://10.10.192.34 -o report.html
```
