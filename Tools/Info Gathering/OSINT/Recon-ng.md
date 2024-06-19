We can start it by running `recon-ng`.
If it's our first time using it, we will need to install the modules we need.

First we need to create a workspace, and enter that workspace
```recon-ng
workspaces create NAME
recon-ng -w NAME
```
Then we will start filling the database with our starting information. If we want to check the names of the tables in our database we use `db schema`. Then we insert the information into the a table
```recon-ng
[recon-ng][redteam] > db insert domains
domain (TEXT): domain.com
notes(TEXT): 
...
```
Then we need to search for modules in the marketplace. We can use the following commands to move around it.
- `marketplace search KEYWORD` to search for available modules with _keyword_.
- `marketplace info MODULE` to provide information about the module in question.
- `marketplace install MODULE` to install the specified module into Recon-ng.
- `marketplace remove MODULE` to uninstall the specified module.
Searching for things like `marketplace search domains` will throw us modules related that will recover certain types of information given a domain like `domains-companies` or `domain-hosts`. Some modules require a key and other dependencies. 
Once we find one or various that we vibe with we can see them by running `modules search` , or `modules load MODULE` to load a specific one from memory. Then we need to see and set the options.
- `options list` to list the options that we can set for the loaded module.
- `options set <option> <value>` to set the value of the option.
Finally we run the module with `run`.