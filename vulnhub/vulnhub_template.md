# Title

Difficulty:: #
> Classified according to [Vulhub difficulty page](https://www.vulnhub.com/difficulty/)

## Target data
- Link:
- CVSS3 :
  > **Warning**: I select the CVSS3 score to start to practice, so is very possible that I made a mistake in the selection, so do not trust of that CVSS3.

## Machine Description


## Summary

#TODO

1. CWE-

#VirtualBox #VMWare #Nmap #CyberChef #HashID #HashCat #Docker #Ghidra #BufferOverflow #Assembler #ROP #PEDA #Pwntools #Python  #Python2 #GDB #Feroxbuster #Ffuf #LinuxKI #Kernel #Kmod #Pinkit #LKMBackdoor #insmod #DB4S #SQLite #rpcbind #NFS #mount #RiteCMS #vhosts #SHA-1 #LinPEAS #setuid #Capabilities #FTP #Net2ftp #WebDAV #MD5 #PUT #Pspy #awk #gtfobins #RPM #Postfix #POP #SquirrelMail #PathTraversal #LFI #NullByteAttack #LogPoisoning #UnixGroups #WebShell #MySQL #WordPress #WPScan #Hydra #iptables #lsblk #Webmin #Backdoor #Joomla #Joomscan #Sentrifugo #Burpsuit #Crunch #Vim #SNMP #snmp-check #UDP #ssh-brute #Perl #Chisel #Tomcat #WAR #stegseek #steganography #SubstitutionCipher #ROT13 #SHA-512 #PHP #open_basedir #disable_functions #MariaDB #GCC #Golang #youtube-dl #ArgumentInjection #nano #WireShark #TCPdump #Tshark #aircrack-ng #IEEE-802-11 #Nginx #Samba #SMB #Smbclient #John #zip2jhon #Sitemagic #systemctl #CMS #Adminer #BigTree #MantisBT #Beautifier #Jenkins #Jetty #Groovy #pycryptodome #dpkg-deb #find #ruby #Polkit #SSRF #HTTP3 #QUIC #quiche #BoringSSL #cargo #rustc #curl_exec #RCE #cp #Mozilla #firefox_decrypt #Java #JD-GUI #ReCaf #AES #Cryptography #GPG #ncrack #tmux

## Enumeration
When I run the target machine in VirtualBox (see the [setup vulnhub machines](../setup-vulnhub.md), then I identify in the target prompt the IP `192.168.2.xxx`:

When I run the target machine in VirtualBox (see the [setup vulnhub machines](../setup-vulnhub.md), and on my target machine, I run the `netdiscover` command:
```shell
$ sudo netdiscover -i enp0s8 -r 192.168.2.0/24
```
Then I compare the MAC with that of the target VirtualBox configuration, and I find out that the IP is `192.168.2.xxx`


When I run the target machine in VMware Workstation 17 Player (see the [setup vulnhub machines](../setup-vulnhub.md), and on my target machine, I run the `netdiscover` command:
```shell
$ sudo netdiscover -i enp0s3 -r 192.168.56.0/24
```
Then I compare the MAC with that of the target VMware configuration, and I find out that the IP is `192.168.56.xxx`

## Normal use case

## Static detection

## Dynamic detection

## Exploitation

## Maintaining access

## Lateral movement

## Pivoting

## Privilege escalation

## Alternative Privilege escalation

## Designed PATH

## Extraction

## Remediation
