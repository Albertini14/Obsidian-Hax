Is a wordlist generator that creates custom wordlists based on a web page content

```sh
cewl SERVER
```

|Option|Description|
|-|-|
|`-d n`|specifies spidering depth|
|`-w LIST.txt`|writes to output|
|`-m n`|min length of characters|
|`-x n`|max length of characters|
|`-a`|if the target site is behind a login|
|`--with-numbers`|will append numbers to words|
|`--extension .EXT`|appends custom extensions to each word|
|`--offsite`|allows CeWL to spider to external sites|