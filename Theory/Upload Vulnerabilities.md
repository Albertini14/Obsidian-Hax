Uploading files has become an integral part of how we interact with web applications. But when handled badly, file uploads can also open up severe vulnerabilities in the server. This can lead to anything from relatively minor up to RCE. With unrestricted upload access to a server (and the ability to retrieve data), an attacker could deface or otherwise alter existing content, including injecting malicious webpages, which could lead to XSS or CSRF.

# Methodology
Step by step process
1. Look at the website as a whole. Look for indicators of what languages and frameworks are in place. Maybe using tools like [[Wappalyzer]], [[GoBuster]] or [[Nikto]]. Intercept responses with [[Burp]] and look for headers such as `server` or `x-powered-by`. Look for vectors of attack like an upload page
2. Upon finding one, inspect it. Look at source code for client-side scripts, to disable or bypass them.
3. Upload files, starting with ones that should get accepted. From here we can use it to see how it is handled, see if we can access it through an `uploads` folder? can we do some sort of directory indexing? is it embedded in a page somewhere? does the server has a naming scheme in place? Here [[GoBuster]] glows bright. 
	- We can use the `-x` flag to look for specific extensions. For example we could upload a png image and then search for `-x png` to see if the server is changing the name of our files completely.
4. Knowing that our uploaded files can be accessed and where to find them. We can start crafting our payloads. Avoiding any kind of client-side filtering and testing for the server side ones.
Assuming that our files get stopped by the server, here are some tips on to what kind of filters may be in place.
- If we can successfully upload a file with a totally invalid file extension `shell.sldfkjsld` then it may be possible that a **blacklist** is in place. And if it fails then file extensions will be operating on a **whitelist**.
- Try re-uploading our accepted file, but changing the magic numbers to something that should get filtered. If the upload fails then magic filtering must be in place.
- Again, re-upload but this time changing the MIME type to something that should be filtered. If it fails then MIME is in place.
- Enumerating for file length filters is also an option. Although unlikely in services that expect images, we could try uploading progressively larger files until we hit the limit.

# Overwriting Existing Files
When files are uploaded to the server, a range of checks should be carried out to ensure that the file will not overwrite anything which already exists on the server. Common practice is to assign the file with a new name, whether this be a random string or with the date and time added to the start or end of the original name. File permissions also come into play when protecting existing files form being overwritten. However if this precautions are not taken, then we might potentially be able to overwrite existing files on the server.

# Uploading and Executing Shells
Now let's get into the real game. Obtaining RCE. Whilst this is likely to be as a low-privileged user account (such as `www-data`), we could try and escalate from here. This tends to be exploited by uploading a program written in the same language as the back-end of the website (or any other that the website could understand and execute). In older system this would be PHP, but in modern sites languages like Python Django and JS in the form of Node.js have become more popular. It's worth noting that in a routed application (An application where the routes are defined programmatically rather than being mapped to the file-system), this method of attack becomes more complicated and less likely and most modern web frameworks are routed programmatically.
There are two basic ways to achieve RCE: webshells and reverse/bind shells. Ideally a fully tty reverse shell is our go to, but there may be instances where a webshell may be the only option (if a file length limit is in place, or if firewall rules prevent any network-based shells).
Generally we will be looking to upload a shell of either kind, then activating it, via navigating directly to the file if the server allows it (non-routed applications), or by otherwise forcing the webapp to run the script for us (routed applications).

## Web Shells
Let's say that we found the directory where files get uploaded, with [[GoBuster#Dir mode|GoBuster]], and the server is running with PHP back-end. To create our [[Shells#WebShells|Web Shell]], can be as simple as taking a parameter and executing it as a system command like so:
```php
<?php echo system($_GET["cmd"]); ?>
```
We can then upload it to a site and as we already have its location displaying it through the URL like so:
```
http://vulnerable.server/uploads/webshell.php?cmd=whoami
```
Note that we gave the variable `cmd` the command `whoami` that will be display by the page as it echoes the output of the system command in our webshell. From here we could read, navigate files or try and upgrade to a reverse shell. 

## Reverse Shells
The process for uploading a reverse shell is almost identical to that of uploading a webshell.
Here we can use the [Pentest Monkey](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php) reverse shell which comes by default on Kali and a is also in [revshells](https://www.revshells.com). With it we just need to change both the IP and the port and it is good to go. Similarly, we upload the shell set up a [[Netcat|listener]] and activate it by navigating to its location
```
http://vulnerable.server/uploads/shell.php
```
And we have RCE!
From here we could go for both escalation and stabilization of our shell.

# Types of Filtering
## Extension Validation
File extensions are used (theoretically) to identify the contentes of a file. In practice they are very easy to change. MS Windows still uses them to identify file types, although Unix based system tend to relay on other methods. Filters that check for extensions work in one of two ways. 
- Blacklist extensions
- Whitelist extensions

## File Type Filtering
Similar to extension validation, but more intensive, file type filtering looks, to verify that the contents of a file are acceptable to upload. These can be done in two ways:
### MIME validation
Multipurpose Internet Mail Extension types are used as n identifier for files, originally when transferred as attachments over email, but now also when files are being transferred over HTTP(S). The MIME type for a file upload is attached in the header of the request and looks something like:
```
POST / HTTP/1.1
Host: vulnerable.site
...
...
...
...
Content-Disposition: form-data; name="fileToUpload"; filename="image.jpg"
Content-Type: image/jpeg
```
This follow the format of `<type>/<subtype>`. In the request above we can see that the image `image.jpg` was uploaded to the server. As a legitimate JPEG image the MIME type for this upload was `image/jpeg`. The MIME type for a fiel can be checked client-side and/or server-side. However, as MIME is based on the extension of the file, it is trivial to bypass
### Magic Number validation
[Magic numbers](https://en.wikipedia.org/wiki/List_of_file_signatures) are the more accurate way of determining the contents of a file, although they still are possible to fake. The "magic number" of a file is a string of bytes at the very beginning of the file content which identify the content. For example, a PNG fiel would have these bytes at the very top
```
89 50 4E 47 0D 0A 1A 0A
```
Unlike Windows, Unix uses magic numbers for identifying files. Now, when dealing with fiel uploads, it is possible to check the magic number of the uploaded file to ensure that it is safe to accept. This is not a permanent solution but is more effective than just checking the extension of a file.

## File Length Filtering
File length filters are used to prevent huge files from being uploaded to the server via an upload form. In most cases this will not be a problem when uploading shells, but it's still worth keeping in mind that if an upload form only expects a very small file to be uploaded, there may be a length filter in place to ensure that the file length requirement is met.

## File Name Filtering
As mention previously, files uploaded should be unique, normally this would mean adding a random string to the file name, however, an alternative strategy would be to check if a file with the same name already exists on the server, and give the user an error. Additionally, files names should be sanitised on upload to ensure that the don't contain any characters that may cause problems on the file system when uploaded ([[Null Byte|null bytes]], forward slashes, semicolons or unicode characters). 
On a well administered system, our uploaded files are unlikely to have the same name we gave them before uploading, so we may have to go hunting for our shell.

## File Content Filtering
More complicated filtering systems may scan the full contents of an uploaded file to ensure that it's not spoofing its extension, MIME type and Magic number. This is incredibly more complex 

# Bypassing...
## Client-Side Filtering
This tends to be the easiest type to bypass as it occurs entirely on our machine, so it's easier to alter. 
### Turn off JS
Stupid easy, this will work if the site does not require JS in order to provide basic functionality. If turning it off will prevent the site from working then other methods are preferable.
### Intercept and modify the incoming page
Using something like [[Burp|Burpsuite]] we can intercept the incoming web page and remove the JS filter before it has a chance to run. 
One example will be to intercept the standard loading page GET request. Then we check for the response for this request which will contain the normal HTML code for the webpage. We can then look for a `<script>` tag that handles the filtering and commenting it out or outright removing the code.

### Intercept and modify the file upload
The previous method, works before the webpage is loaded, while this one allows the webpage to load as normal. It instead intercepts the file upload after it's already passed as a legitimate file, and we change it into our malicious one.
For PHP files and the MIME type filtering, we could first upload our shell as a `.jpg`, then intercept the upload request and change both the name of the file inside the request to `shell.php` and the `Content-Type: image/jpeg` to `text/x-php`. Finally we just forward the request and our shell is uploaded.

### Send the file directly to the upload point
Why bother why the webpage and filters when we can send the file directly using things like `curl`. Posting data directly to the page which contains the code for handling the file upload is another effective method for completely bypassing a client side filter. The general syntax for something like this would be:

```Shell
curl -X POST -F "submit:<value>" -F "<file-parameter>:@<path-to-file>" <site>
```

To do this we would first intercept a successful upload to see the parameters being used in it, to then use them in the command. 

## Server-Side Filtering
Now unto the real shit. What to do if we can't manipulate or even see the code. Testing is the core idea in which bypassing server side filtering is built upon of.
There is not a methodology on how to do this as it entirely depends on what type of filtering is being used and how they implemented it. So try and fail to develop a theory on how the filtering may work is our best bet. Still there are some tricks that may help us in a variety of cases.
### File extensions
When dealing with a server that filters based on the extension of the file. We could approach this in many ways:
- If they use a blacklist for `.php and .phtml` files we could try other less common extensions for PHP that may still work like
	- `.php3`, `.php4`, `.php5`, `.php7`, `.phps`, `.php-s`, `.pht` and `.phar`
- We could try to insert a valid extension in the name of the file in the case that a whitelist code is checking if a valid extension is in string of a file name like `shell.jpg.php`
### Magic numbers
If we encounter magic filtering, we should try to change the magic numbers of our payload. To do this, we can take a look at [list](https://en.wikipedia.org/wiki/List_of_file_signatures), if one type has various options it shouldn't matter which one we use. Now, we could add the ASCII representation of these digits but generally it is easier to work directly with the hex.
First we can use the `file` command to check the file type of our payload. Then we can append four random characters at the start of our payload like so:
```php
AAAA
<?php
...
...
```
We then save the file and reopen it with `hexedit`. We can now see four sets of values that will repeat at the start of the file type. Finally we just need to change these characters into our [magic numbers](https://en.wikipedia.org/wiki/List_of_file_signatures). jpg ej
```
FF D8 FF DB ......
```
Finally if we use the `file` command once again we should see that we have successfully spoofed the file type of our payload.
# Content Type Validation