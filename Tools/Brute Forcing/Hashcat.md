# Wordlist
Cracks a given hash in the `wordlist` attacking mode `-a`, of a specific type `-m` given a dictionary
```shell
hashcat -a 0 hash.txt -m 1400 dict.txt
```

If we already cracked a hash, we can append `--show` to the command that we used to see the cracked value.

# Combinatory
Combines two dictionaries to test all posible combinations between them to crack a hash, we can use rules to apply to each dictionary separately. For example the following will take the left dictionary and append `-` at the end of each entry and the right will be appended with `01` at the end as well creating the following `word-word01` for each attempt at cracking the hash. 
```shell
hashcat -a 1 hash.txt leftdict.txt -j '$-' right.txt k '$01' -m 1400  
```
We could also use the following to only create a dictionary based on the combinations of two dictionaries without cracking a hash.
```shell
hashcat -a 1 --stdout left.txt -j '$ ' right.txt > combination.txt    
```

# Brute Force
We can brute force passwords using the charsets provided

| ?   | Charset                             |          |
| --- | ----------------------------------- | -------- |
| l   | abcdefghijklmnopqrstuvwxyz          | [a-z]    |
| u   | ABCDEFGHIJKLMNOPQRSTUVWXYZ          | [A-Z]    |
| d   | 0123456789                          | [0-9]    |
| h   | 0123456789abcdef                    | [0-9a-f] |
| H   | 0123456789ABCDEF                    | [0-9A-F] |
| s   | !"#$%&'()*+,-./:;<=>?@[\\]^_\`{\|}~ |          |
| a   | ?l?u?d?s                            |          |
| b   | 0x00 - 0xff                         |          |
  
So by using
```shell
hashcat -a 3 ?u?l?l?d --stdout
```
We will get all combinations of a single uppercase character, followed by 2 lowercases and one number. (`Aaa0-Zzz9`)