```
                                                                                    
                                                                                    
 $$$$$$\  $$\   $$\  $$$$$$\   $$$$$$\   $$$$$$\   $$$$$$\  $$\  $$\  $$\ $$$$$$$\  
$$  __$$\ $$ |  $$ |$$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\ $$ | $$ | $$ |$$  __$$\ 
$$ /  $$ |$$ |  $$ |$$ /  $$ |$$$$$$$$ |$$ |  \__|$$ /  $$ |$$ | $$ | $$ |$$ |  $$ |
$$ |  $$ |$$ |  $$ |$$ |  $$ |$$   ____|$$ |      $$ |  $$ |$$ | $$ | $$ |$$ |  $$ |
$$$$$$$  |\$$$$$$$ |$$$$$$$  |\$$$$$$$\ $$ |      $$$$$$$  |\$$$$$\$$$$  |$$ |  $$ |
$$  ____/  \____$$ |$$  ____/  \_______|\__|      $$  ____/  \_____\____/ \__|  \__|
$$ |      $$\   $$ |$$ |                          $$ |                              
$$ |      \$$$$$$  |$$ |                          $$ |                              
\__|       \______/ \__|                          \__|                              


```

***

All the following console commands refer to linuxoid operating systems. They have been tested using Manjaro/Arch Linux.
For Windows instructions see the documentation of the corresponding application.

# Setup

1. Install Metasploit Framework + PostgreSQL.
1. Start and setup the Postgres database for Metasploit. To check, start `msfconsole` and issue `db_status` to the command line.
1. Install tcpdump (on Linux) or WinDump (on Windows).
1. Install MongoDB.
1. Create a virtual environment with `python3 -m venv env` and activate it `source env/bin/activate`.
1. Install the application's dependencies with `pip install -r requirements.txt`.
1. Make the Main class and start scripts executable with `chmod +x pyperpwn.py startup_arch.sh startup_debian.sh`.


# Application Start

## Start dependencies

In general, it's recommendable to restart MSFRPCD with every restart of the application.

#### Manually
1. Start PostgreSQL (for Metasploit) using `systemctl start postgresql` or `service postgresql start`.
1. Start the MSFRPC Daemon with `msfrpcd -P <pwd> -S -f -a 127.0.0.1`
1. Start MongoDB using `systemctl start mongodb` or `service mongodb start`.

#### Using scripts
- Using Manjaro/Arch Linux: `sudo ./startup_arch.sh`
- Debian/Kali Linux: `sudo ./startup_debian.sh`

## Start

Execute the application using `sudo ./pyperpwn.py -p <pwd>`. For further configuration check out the application's parameters `./pyperpwn.py -h`. Exploit will only be executed with the `-e` flag. Running the application without this flag can be considered a ''dry run''.
Running as `sudo` is required because of the call to `tcpdump`.
In  case you've started MSFRPC using the supplied script, you'll find the password for connecting in the script's first line.

## Input
The application takes two files as input:
#### Vulnerability Scanner Report
An example for the required format can be found in the directory ```vuln_reports```. All shown columns are obligatory, additional columns will be ignored.
#### Exploit Classification File
An example for the required format can be found in the directory ```exploit_classification```. All shown columns are obligatory, additional columns will be ignored.
If no value provided for a specific exploit, a precise evaluation of success cannot be performed.

# Configuration
## DB
In case you want to use a MongoDB instance at a non-default location, change the ```db_config``` variable in ```config.py```.
## General
Some more parameters can be changed in ```config.py```:
- Speed step values
- name search similarity threshold
- console output colours 

# Known Issues
- ``` Bind failed: Port already in use```
Happens sometimes, if a Metasploit handler does not free the port or is still listening (which is nothing the pyperpwn can change in any way). Try to restart MSFRPCD and rerun the application, maybe switch to another LPORT or use bind payloads for the concerned exploits. Maybe also consider adding the functionality to randomize the LPORT choice (in a given port range). This is probably because pymetasploit returns the exploit output in some cases before the exploit execution has actually finished.
- Sessions are not yet closed via the function offered by pymetasploit3, but via a direct command to the concerned shell. This should be changed.
