# Remote Access Service

The need for remote administration of computer systems led to the development of various software packages and protocols. For example:

- SSH: SSH stands for Secure Shell. It was initially used in Unix-like systems for remote login. It provides the user with a command-line interface (CLI) that can be used to execute commands.
- RDP: RDP stands for Remote Desktop Protocol; it is also known as Remote Desktop Connection (RDC) or simply Remote Desktop (RD). It provides a graphical user interface (GUI) to access an MS Windows system. When using Remote Desktop, the user can see their desktop and use the keyboard and mouse as if sitting at the computer.
- VNC: VNC stands for Virtual Network Computing. It provides access to a graphical interface which allows the user to view the desktop and (optionally) control the mouse and keyboard. VNC is available for any system with a graphical interface, including MS Windows, Linux, and even macOS, Android and Raspberry Pi.

All of these require authentication, in which we use usernames and passwords to authenticate ourselves.

## Attacking Passwords

The following are some of the ways used in attacks against passwords:

- Shoulder Surfing: Looking over the victim’s shoulder might reveal the pattern they use to unlock their phone or the PIN code to use the ATM. This attack requires the least technical knowledge.
- Password Guessing: Without proper cyber security awareness, some users might be inclined to use personal details, such as birth date or daughter’s name, as these are easiest to remember. Guessing the password of such users requires some knowledge of the target’s personal details; their birth year might end up as their ATM PIN code.
- Dictionary Attack: This approach expands on password guessing and attempts to include all valid words in a dictionary or a word list.
- Brute Force Attack: This attack is the most exhaustive and time-consuming, where an attacker can try all possible character combinations.

Let’s focus on dictionary attacks. Over time, hackers have compiled one list after another of passwords leaked from data breaches. One example is RockYou’s list of breached passwords (usually found at `/usr/share/wordlists/rockyou.txt` for example in Kali Linux distributions). The choice of the word list should depend on your knowledge of the target. For instance, a French user might use a French word instead of an English one. Consequently, a French word list might be more promising.
RockYou’s word list contains more than 14 million unique passwords. Even if we want to try the top 5%, that’s still more than half a million. We need to find an automated way.

## Hacking an Authentication Service

First, use Nmap to scan the target machine to look for active listening services i.e. SSH, VNC, RDP. Then we use an automated way to try the common passwords or the entries from a word list, in this case we use `THC Hydra`. Hydra supports many protocols, including SSH, VNC, FTP, POP3, IMAP, SMTP, and all methods related to HTTP.

### Using Hydra

General command-line syntax:

    ```
    hydra -l username -P wordlist.txt server service
    ```
where:

- `-l username`: `-l` should precede the `username`, i.e. the login name of the target. You should omit this option if the service does not use a username.
- `-P wordlist.txt`: `-P` precedes the `wordlist.txt` file, which contains the list of passwords you want to try with the provided username.
- `server` is the hostname or IP address of the target server.
- `service` indicates the service in which you are trying to launch the dictionary attack.

There are some extra optional arguments that you can add:

- `-V` or `-vV`, for verbose, makes Hydra show the username and password combinations being tried. This verbosity is very convenient to see the progress, especially if you still need to be more confident in your command-line syntax.
- `-d`, for debugging, provides more detailed information about what’s happening. The debugging output can save you much frustration; for instance, if Hydra tries to connect to a closed port and timing out, `-d` will reveal this immediately.

Examples:

    ```
    hydra -l mark -P /usr/share/wordlists/rockyou.txt 10.10.41.165 ssh
    hydra -l mark -P /usr/share/wordlists/rockyou.txt ssh://10.10.41.165
    ```
    These two are equivalent.
