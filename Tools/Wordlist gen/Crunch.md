Serves the purpose of creating a wordlist for us to try to crack a password
```shell
crunch MIN_LEN MAX_LEN CHARACTERS -o WORDLIST.txt
```

It also lets us specify a character set using the `-t` option to combine words of our choice. With it, it will let us specify a pattern where only the following symbols are going to change
- `@` - lower case alpha characters
- `,` - upper case alpha characters
- `%` - numeric characters
- `^` - special characters including space
So doing
```
crunch 7 7 -t @rrow%%
```
will create something like
```
arrow00
brrow00
crrow00
...
zrrow97
zrrow98
zrrow99
```

For any other thing check manpage
