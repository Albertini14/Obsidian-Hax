Tool designed for brute-forcing web applications. It can be used to find resources not linked directories, servlets, scripts, etc, brute-force GET and POST parameters for checking different kinds of injections, brute-force forms parameters and fuzzing

```sh
wfuzz [OPTIONS] -z PAYLOAD,PARAMS <url>
```

|options|description|
|-|-|
|`-z PAYLOAD,PARAMS`||
|`-w WORDLIST.txt`|alias for `-z file,WORDLIST.txt`|
|`--hs "ERROR"`|hides responses containing the string displayed for wrong login attempts|
|`-u URL`|specifies url|
|`-d "username=FUZZ&password=FUZ2Z"`|provides POST data format where FUZZ and FUZ2Z will be replaced by previous wordlists|