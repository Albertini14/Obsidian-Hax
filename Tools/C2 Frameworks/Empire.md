# Getting Started
### Starting Empire
Once both Empire and Starkiller are installed we can start both servers. Being by starting Empire with the instructions below.  
1. `cd /opt/Empire`
2. `./empire --rest`
### Starting Starkiller  
Once Empire is started follow the instructions below to start Starkiller.  
1. `cd /opt`
2. `./starkiller-0.0.0.AppImage`  
3. Login to Starkiller
### Default Credentials
`Url: 127.0.0.1:1337`
`User: empireadmin`
`Pass: password123`

# Listeners
Listeners are used in empire similar to how they are used in any other normal listener. These listeners can have some very useful functionality that can help with agent management as well as concealing our traffic / evading detections. Below we can find an outline of the available listeners and their uses.

- http - This is the standard listener that utilizes HTTP to listen on a specific port.

The next four commands use variations of HTTP COMs to generate a listener.

- http_com - Uses the standard HTTP listener with an IE COM object.
- http_foreign - Used to point to a different Empire server.
- http_hop - Used for creating an external redirector using PHP.
- http_mapi - Uses the standard HTTP listener with a MAPI COM object.

The next five commands all use variations of built out services or have unique features that make them different from other listeners.

- meterpreter -  Used to listen for Metasploit stagers.
- onedrive - Utilizes OneDrive as the listening platform.
- redirector - Used for creating pivots in a network.
- dbx - Utilizes Dropbox as the listening platform.
- http_malleable - Used alongside the malleable C2 profiles from BC-Security.

We can also create custom malleable c2 listeners that act as beacons to emulate certain threats or APT's

# Stagers
In here we have quite a few options, firstly the platform, multi, OSx and Windows. Secondly the stager itself, here we ha quite the range, some of the ones that have a general purpose are.
- multi/launcher - A fairly universal stager that can be used for a variety of devices.
- windows/launcher_bat - Windows Batch file
- multi/bash - Basic Bash Stager
We can also use stagers for more specific applications similar to the listeners. These can be anything from macro code to ducky code.
- windows/ducky - Ducky script for the USB Rubber Ducky for physical USB attacks.
- windows/hta - HTA server an HTML application protocol that can be used to evade AV.
- osx/applescript - Stager in AppleScript: Apple's own programming language.
- osx/teensy - Similar to the rubber ducky is a small form factor micro-controller for physical attacks.