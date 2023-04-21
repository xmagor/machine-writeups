# VulnHub Machines
---
## Acknowledgments 💎

I want to extend a special thank you to [Autonomic Mind](https://autonomicmind.com/) for their patronage during my self-training. Thanks to your support, I focused on analyzing and learning from both the machines I solved and the ones I got stuck on.

And also thanks to all who spend time creating those fantastic machines and upload them to make more people can learn of them 💚.

> **Note**: Originally I made the machine reports with a [Gherkins](https://cucumber.io/docs/gherkin/) template, but I modify them to be more confortable in Markdown, thinking in read them with [Obsidian](https://obsidian.md/) and to hold the structure of my [write-ups template](./vulnhub_template.md).
---
## Stadistics 📈
- **Average hour per solution**: `12.20`
- **Calendar time required**: ~ 2 months
- **Total machines**: 27
- **Number of machines solved by difficulty**:
  🟣 **2**  VeryEasy
  🟢 **13**  Easy
  🟡 **11**  Medium
  🔴 **1**  Hard

> **Note**:
> - You can verify some of the statistics on my [user report](https://app.autonomicjump.com/users/criminal-king/).
> - The difficulty is classified according to [VulnHub difficulty page](https://www.vulnhub.com/difficulty/).

### Bests machines 🔥
The **TOP 3** machines that I choose and represented a lot of new things and fun are:

1. [HarryPotter: Nagini](./25-harrypotter-nagini/README.md). This machine gains the first place because it uses the `HTTP3` and the MySQL interaction with `gopher://` URL scheme through an SSRF vulnerability.
2. [Warzone: 3 (Exogen)](./26-warzone-3-exogen/README.md). I love how I could modify the Assembler instructions of the Java `.jar` binaries using the `ReCaF` tool, and it was about cryptography `AES` symmetric encryption.
3. [Cybox: 1.1](./07-cybox-11/README.md). I like how this machine handles multiple virtual hosts and an LFI that escalates to an RCE with a log poison attack, and the bests were this machine opened my eyes with the privilege escalation.

## List machines solved ✅
I listed them in the order I solved them:

| # | Machine | Difficulty | Tags |
| --- | --- | --- | --- |
| 1 | [XPTO System 1](./01-xpto-system-1/README.md) | #Easy | #VirtualBox #Nmap #CyberChef #HashID #HashCat #Docker |
| 2 | [Overflow 1](./02-overflow-1/README.md) | #Easy | #VirtualBox #Nmap #Ghidra #Pwntools #Python #GDB #BufferOverflow #CyberChef |
| 3 | [Ki 1](./03-ki-1/README.md) | #Easy | #VirtualBox #Nmap #HashID #HashCat #Python #Feroxbuster #Ffuf #LinuxKI #Kernel #Kmod #Pinkit #LKMBackdoor #insmod |
| 4 | [Undiscovered 1.0.1](./04-undiscovered-101/README.md) | #Medium | #VirtualBox #Nmap #HashID #HashCat #Ghidra #Python #Feroxbuster #Ffuf #DB4S #SQLite #rpcbind #NFS #mount #RiteCMS #vhosts #SHA-1 #LinPEAS #setuid #Capabilities |
| 5 | [Legacy Hangtuah](./05-legacy-hangtuah/README.md) | #Easy | #VirtualBox #Nmap #CyberChef #HashID #HashCat #Python #Feroxbuster #Ffuf #vhosts #LinPEAS #FTP #WebDAV #Hydra #MD5 #PUT #Pspy #awk #gtfobins |
| 6 | [InfoSecWarrior CTF 2020 01](./06-infosecwarrior-ctf-2020-01/README.md) | #Easy | #VirtualBox #Nmap #Feroxbuster #gtfobins #RPM |
| 7 | [Cybox 1.1](./07-cybox-11/README.md) | #Medium | #VirtualBox #Nmap #CyberChef #HashCat #Ghidra #Python #Feroxbuster #Ffuf #vhosts #setuid #FTP #Net2ftp #WebDAV #gtfobins #Postfix #POP #IMAP #LFI #SquirrelMail #PathTraversal #NullByteAttack #LogPoisoning #UnixGroups #WebShell |
| 8 | [WPWN 1](./08-wpwn-1/README.md) | #Easy | #VMWare #Nmap #HashID #HashCat #Python #MySQL #WordPress #wordpress-plugin #WPScan #Hydra #iptables #lsblk |
| 9 | [Source 1](./09-source-1/README.md) | #VeryEasy | #VMWare #Nmap #Python #Webmin #Backdoor |
| 10 | [View2akill 1](./10-view2akill-1/README.md) | #Medium | #VirtualBox #Nmap #Python #Ffuf #vhosts #SHA-1 #Postfix #WebShell #Joomla #Joomscan #Sentrifugo #Burpsuit #Crunch #Vim #Python2 |
| 11 | [DPWWN 3](./11-dpwwn-3/README.md) | #Easy | #VMWare #Nmap #Ghidra #Pwntools #Python #GDB #MD5 #Burpsuit #SNMP #snmp-check #UDP #ssh-brute #BufferOverflow #ROP #PEDA #Perl #Chisel |
| 12 | [HACKSUDO 1.0.1](./12-hacksudo-101/README.md) | #Medium | #VirtualBox #Nmap #CyberChef #HashID #HashCat #Ghidra #MD5 #Pspy #gtfobins #Tomcat #Backdoor #WAR #stegseek #steganography #SubstitutionCipher #ROT13 #SHA-512 |
| 13 | [UNDERDIST 3](./13-underdist-3/README.md) | #Medium | #VirtualBox #Nmap #Ghidra #BufferOverflow #ROP #PEDA #Pwntools #Python #GDB #Feroxbuster #Ffuf #setuid #Pspy #Postfix #Vim #Perl #Chankro #Python2 #LFI #PHP #open_basedir #disable_functions |
| 14 | [InfoSecWarrior CTF 2020 03](./14-infosecwarrior-ctf-2020-03/README.md) | #Easy | #VirtualBox #Nmap #Ghidra #Python #gtfobins #MySQL #WordPress #WPScan #iptables #Backdoor #MariaDB #GCC #SubstitutionCipher |
| 15 | [DMV 2](./15-dmv2/README.md) | #Medium | #VirtualBox #Nmap #Python #Ffuf #PathTraversal #Burpsuit #PHP #Golang #youtube-dl #ArgumentInjection #otparse #Git |
| 16 | [Noob: 1](./16-noob-1/README.md) | #Easy | #VMWare #Nmap #CyberChef #FTP #gtfobins #stegseek #steganography #SubstitutionCipher #ROT13 #nano |
| 17 | [Tr0ll 3](./17-tr0ll-3/README.md) | #Easy | #VirtualBox #Nmap #CyberChef #Ghidra #Python2 #setuid #FTP #Vim #UDP #WireShark #TCPdump #aircrack-ng #IEEE-802-11 #Nginx |
| 18 | [KB-VULN 3](./18-kb-vuln-3/README.md) | #Medium | #VirtualBox #Nmap #Python #LinPEAS #setuid #gtfobins #PHP #Samba #SMB #Smbclient #John #zip2jhon #Sitemagic #WebShell #systemctl |
| 19 | [Tre: 1](./19-tre-1/README.md) | #Medium | #VMWare #Nmap #HashID #HashCat #Feroxbuster #LinPEAS #MD5 #Pspy #MySQL #PHP #Nginx #CMS #Adminer #BigTree #MantisBT |
| 20 | [PRIMER: 1.0.1](./20-primer-101/README.md) | #VeryEasy | #VirtualBox #Nmap #HashCat #rpcbind #MD5 #Beautifier |
| 21 | [WTF: 1](./21-wtf-1/README.md) | #Easy | #VMWare #Nmap #Feroxbuster #gtfobins #WordPress #WPScan #iptables #PHP #CMS #WebShell |
| 22 | [Leeroy 1](./22-leeroy-1/README.md) | #Easy | #VMWare #Nmap #Python #Ffuf #gtfobins #MySQL #WordPress #WPScan #CMS #Jenkins #Jetty #Groovy #ArgumentInjection #pycryptodome #dpkg-deb #LFI #wget |
| 23 | [hackNos Player v1.1](./23-hacknos-player-v11/README.md) | #Medium | #VirtualBox #Nmap #HashCat #Python #Feroxbuster #LinPEAS #gtfobins #WebShell #MySQL #WordPress #WPScan #Hydra #PHP #MariaDB #GCC #CMS #find #ruby #Polkit |
| 24 | [HackLAB: Vulnix](./24-hacklab-vulnix/README.md) | #Easy | #VMWare #Nmap #rpcbind #NFS #mount #setuid #Postfix #POP #nano #OpenSSH |
| 25 | [HarryPotter Nagini](./25-harrypotter-nagini/README.md) | #Medium | #VirtualBox #Nmap #Ghidra #Python #Python2 #Feroxbuster #Ffuf #vhosts #setuid #gtfobins #PathTraversal #MySQL #Backdoor #Joomla #PHP #CMS #SSRF #HTTP3 #QUIC #quiche #BoringSSL #cargo #rustc #curl_exec #WebShell #RCE #cp #Mozilla #firefox_decrypt |
| 26 | [Warzone: 3 (Exogen)](./26-warzone-3-exogen/README.md) | #Hard | #VirtualBox #Nmap #Python #FTP #Java #JD-GUI #ReCaf #Assembler #TCPdump #AES #Cryptography #GPG |
| 27 | [Panabee: 1](./27-panabee-1/README.md) | #Medium | #VMWare #Nmap #Python #Feroxbuster #Ffuf #vhosts #setuid #FTP #Postfix #Samba #SMB #Smbclient #ncrack #tmux |

