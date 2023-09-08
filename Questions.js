var questions = [
  {
    question: " What is the acronym for OSPF?",
    answers: {
      a: 'open site PPI Flaws',
      b: 'Open SMB Port Flaws',
      c: 'Open Shortest Port First',
      d: 'Operating System Path First',
      e: 'Open Shortest Path First'
    },
    correctAnswer: 'e'
  },
  {
    question: "What is the acronym for SSL?",
    answers: {
      a: 'Secure Security Layer',
      b: 'Secure Shell',
      c: 'Secure Sockets Layer'
    },
    correctAnswer: 'c'
  },
  {
      question: "What attack exploits the system by pretending to be a legitimate user or different systems, they can send a data packet containing a bug to the target system in order to exploit a vulnerability?",
      answers: {
          a: 'Trojan Horse',
          b: 'Malware',
          c: 'Spoofing'
      },
      correctAnswer: 'c'
  },
  {
      question: "What attack exploits the system by pretending to be a legitimate user or different systems, they can send a data packet containing a bug to the target system in order to exploit a vulnerability?",
      answers: {
          a: 'Trojan Horse',
          b: 'Malware',
          c: 'Spoofing'
      },
      correctAnswer: 'c'
  },
  {
      question: "What is more complex in nature POP3 or IMAP?",
      answers: {
          a: 'POP3',
          b: 'IMAP'
      },
      correctAnswer: 'b'
  },
  {
      question: ". ___ it is utilised to handle the sending of emails.",
      answers: {
          a: 'POP',
          b: 'IMAP',
          c: 'SMTP'
      },
      correctAnswer: 'c'
  },
  {
      question: "Ethical hackers; they use their skills to improve security by exposing vulnerabilities before malicious hackers",
      answers: {
          a: 'Hacktivist',
          b: 'White Hat',
          c: 'Black Hat',
          d: 'Suicide Hackers',
          e: 'State-Spondored Hacker',
          f: 'Gray Hat',
          g: 'CyberTerrorist',
          h: 'Script Kiddie/Skiddies'
      },
      correctAnswer: 'b'
  },
  {
      question: "What layer does IRC, SSH and DNS operate on?",
      answers: {
          a: '7. Application',
          b: '6. Presentation',
          c: '5. Session',
          d: '4. Transport',
          e: '3. Network',
          f: '2. Data-Link',
          g: '1. Physical'
      },
      correctAnswer: 'a'
  },
  {
      question: "What is the default port for HTTPS?",
      answers: {
          a: '80',
          b: '445',
          c: '443',
          d: '88'
      },
      correctAnswer: 'c'
  },
  {
      question: "What is the difference between encoding and encryption if there is one",
      answers: {
          a: 'There is no difference both enoding and encryption require keys',
          b: 'encrypted files can only be decrypted by keys. However, encoded data can be decoded immediately without keysare'
      },
      correctAnswer: 'b'
  },
  {
      question: "Successful responses",
      answers: {
          a: '100-199',
          b: '200-299',
          c: '300-399',
          d: '400-499'
      },
      correctAnswer: 'b'
  },
  {
      question: "What will identify checking hashes identify?",
      answers: {
          a: 'Identify if computer files have been changed',
          b: 'Identify if theres a breach',
          c: 'Identify if hashes are stored correctly'
      },
      correctAnswer: 'a'
  },
  {
      question: "What is classed as a server-side attack?",
      answers: {
          a: 'XSS(Cross Site Scripting)',
          b: 'Directory Traversal',
          c: 'SQL Injection'
      },
      correctAnswer: 'c'
  },
  {
      question: "Where does ARP store informations locally?",
      answers: {
          a: 'System32 folder',
          b: 'Storage Unit',
          c: 'arp-cache',
          d: 'Database'
      },
      correctAnswer: 'c'
  },
  {
      question: "What tools that interact with SMB allow null session connectivity?",
      answers: {
          a: 'SMBclient, smbmap, rpcclient- and enum4linux',
          b: 'DNSrecon, dig and nslookup',
          c: 'Burp, Curl and FTP'
      },
      correctAnswer: 'a'
  },
  {
      question: "What tools can download web pages for further inspection?",
      answers: {
          a: 'wget and curl',
          b: 'Nessus',
          c: 'NMAP'
      },
      correctAnswer: 'a'
  },
  {
      question: "What is a list of publicly disclosed vulnerabilities and exposures that is maintained by MITRE?",
      answers: {
          a: 'CIDR(Classless Inter-Domain Routing)',
          b: 'OWASP(Open Web Application Security Project)',
          c: 'CVSS(Common Vulnerability Scoring System)',
          d: 'CVE(Common Vulnerabilities Exposures)'
      },
      correctAnswer: 'd'
  },
  {
      question: "Does HTTP being stateless make cookies useful?",
      answers: {
          a: 'Yes',
          b: 'No'
      },
      correctAnswer: 'a'
  },
  {
      question: "What attacks are TLS 1.0 (AES Ciphers) affected by?",
      answers: {
          a: 'SQL Injection',
          b: 'POODLE',
          c: 'HEARTBLEED',
          d: 'BEAST'
      },
      correctAnswer: 'd'
  },
  {
      question: "What does not support listing files and therefore requires guesswork or wordlists to download files from it's server?",
      answers: {
          a: 'NFS',
          b: 'TFTP',
          c: 'SSH',
          d: 'FTP',
          e: 'SMB',
          f: 'SFTP'
      },
      correctAnswer: 'b'
  },
  {
      question: "What is the blocksize of the DES encryption cipher?",
      answers: {
          a: '256bits',
          b: '2048bits',
          c: '128bits',
          d: '196bits',
          e: '64bits'
      },
      correctAnswer: 'e'
  },
  {
      question: ". Someone who hacks for a cause; political agenda",
      answers: {
          a: 'Suicide Hackers',
          b: 'State-Sponsored',
          c: 'Hacktivist',
          d: 'Black Hat',
          e: 'CyberTerrorist'
      },
      correctAnswer: 'c'
  },
  {
      question: "The SSLstrip program can compromise the intergrity or confidentiality of the data-in-transit",
      answers: {
          a: 'Integrity',
          b: 'Confidentiality'
      },
      correctAnswer: 'b'
  },
  {
      question: "What is the Active Directory database file on a windows system?",
      answers: {
          a: 'AD.DB.F',
          b: 'System32',
          c: 'NTDS.dit'
      },
      correctAnswer: 'c'
  },
  {
      question: "Recognises an actor's threat i.e background check, CCTV",
      answers: {
          a: 'Preventive Control',
          b: 'Recovery',
          c: 'Detective Control',
          d: 'Deterrent Control',
          e: 'Compensating Control'
      },
      correctAnswer: 'c'
  },
  {
      question: "What offers better protection LM (Lan Manager) or NTLM (New Technology Lan Manager)?",
      answers: {
          a: 'LM',
          b: 'NTLM'
      },
      correctAnswer: 'b'
  },
  {
      question: "What is more secure, Asymmetric or symmetric cryptography?",
      answers: {
          a: 'Asymmetric Cryptography',
          b: 'Symmetric Cryptography',
          c: 'Both are equal'
      },
      correctAnswer: 'a'
  },
  {
      question: "What class is the subnet mask 255.255.0.0 in?",
      answers: {
          a: 'Class A',
          b: 'Class B',
          c: 'Class C',
          d: 'Class D',
          e: 'Class E'
      },
      correctAnswer: 'b'
  },
  {
      question: "Why is it not recommended to brute force credentials?",
      answers: {
          a: 'Account Lockout Policies',
          b: 'The Windows system will crash',
          c: 'it is recommended'
      },
      correctAnswer: 'a'
  },
  {
      question: "Where would you find the Security Accounts Manager (SAM) file on a microsoft Windows operating system?",
      answers: {
          a: 'Powershell',
          b: 'Command Line',
          c: 'C:\\Windows\\System32\\Config\\',
          d: 'C\\Windows\\System32\\Folder\\'
      },
      correctAnswer: 'c'
  },
  {
      question: "What is the acronym for OWASP?",
      answers: {
          a: 'The Open Web Application Security Project',
          b: 'The Open Wired Application Security Project'
      },
      correctAnswer: 'a'
  },
  {
      question: "Is RC4 insecure",
      answers: {
          a: 'Yes',
          b: 'No'
      },
      correctAnswer: 'a'
  },
  {
      question: "What uses UDP port 500, IP protocol 50 and 51?",
      answers: {
          a: 'IPsec',
          b: 'POP3',
          c: 'FTP',
          d: 'SMTP',
          e: 'DNS'
      },
      correctAnswer: 'a'
  },
  {
      question: "Keeping systems and data from being accessed, seen, read to anyone who is not authorised to do so.",
      answers: {
          a: 'Confidentiality',
          b: 'Integrity',
          c: 'Availability',
          d: 'Authenticity',
          e: 'Accountability',
          f: 'Non-Repudiation',
          g: 'Reliability'
      },
      correctAnswer: 'a'
  },
  {
      question: "To crack Linux passwords requires both the /etc/shadow file and the ...",
      answers: {
          a: 'SYSTEM file',
          b: '/etc/passwd',
          c: '/etc/hosts'
      },
      correctAnswer: 'b'
  },
  {
      question: "True or False: OSPF is a routing protocol for Iternet Protocol (IP) networks",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: "True or false: base64 encoding is not designed for security encryption but for the storage and transit of data (such as binary to ascii).",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: " What changes cache on a machine to redirect requests to a malicious server",
      answers: {
          a: 'ARP Poisoning',
          b: 'XSS',
          c: 'DNS Poisoning'
      },
      correctAnswer: 'c'
  },
  {
      question: "What am I? A memory integrity, prevents attacks from inserting malicious code into high-security processes",
      answers: {
          a: 'Microsoft Defender Smartscreen',
          b: 'Message Integrity Codes(HMAC)',
          c: 'Strict Transport Security',
          d: 'Core Isolation',
          e: 'TPM(Trusted Platform Module)'
      },
      correctAnswer: 'd'
  },
  {
      question: "principle 1 - Lawfulness, fairness and transparency \
      principle 2- purpose limitation\
      principle 3- Data mnimisation\
      principle 4- accuracy\
      principle 5- storage limitation\
      principle 6- integrity and confidentiality\
      principle 7",
      answers: {
          a: 'Authenticity',
          b: 'Availability',
          c: 'Accountability',
          d: 'Account Storage'
      },
      correctAnswer: 'c'
  },
  {
      question: "What attack involves automating the submission of every possible combination of characters?",
      answers: {
          a: 'Brute Force',
          b: 'Guessing',
          c: 'Dictionary Attack',
          d: 'Rainbow Tables'
      },
      correctAnswer: 'a'
  },
  {
      question: "What is the function of POP and IMAP?",
      answers: {
          a: 'To retrieve emails',
          b: 'To recieve emails',
          c: 'For the transfer of email between a client and a mail server'
      },
      correctAnswer: 'c'
  },
  {
      question: "What is the Guest RID in windows?",
      answers: {
          a: '501',
          b: '5000',
          c: '502',
          d: '500',
          e: '250'
      },
      correctAnswer: 'a'
  },
  {
      question: "What are the 2 protocols used for network authentication in Windows Domains?",
      answers: {
          a: 'SMB and RDP',
          b: 'SMB and NetBIOS',
          c: 'SSH and Telnet',
          d: 'Kerberos and NetNTLM'
      },
      correctAnswer: 'd'
  },
  {
      question: "What is the hash value for MD5 hashing algorithm?",
      answers: {
          a: '192',
          b: '128',
          c: '2048',
          d: '56'
      },
      correctAnswer: 'b'
  },
  {
      question: "What is the default privilege of an IIS 6 server?",
      answers: {
          a: 'IUSR_Computername',
          b: 'Local System',
          c: 'Admin'
      },
      correctAnswer: 'a'
  },
  {
      question: "Attackers enumerate this service to extract information about network resources such as hosts, routers, devices, shares. In addition, they enumerate this service for network information such as ARP tables, routing tables, device specific information and traffic statistics.",
      answers: {
          a: 'SMTP',
          b: 'TELNET',
          c: 'SNMP',
          d: 'FTP'
      },
      correctAnswer: 'c'
  },
  {
      question: "What am I? I am a key exchange protocol that enables two parties communicating over public channel to establish a mutual secret without it being transmitted over the internet",
      answers: {
          a: 'Diffie-Hellman',
          b: 'Elliptic curv',
          c: 'RSA',
          d: 'Cramer-Shoup',
          e: 'YAK'
      },
      correctAnswer: 'a'
  },
  {
      question: "What port does Kerberos operate on?",
      answers: {
          a: '3389',
          b: '389',
          c: '88',
          d: '445'
      },
      correctAnswer: 'c'
  },
  {
      question: "What is the strongest Encryption algorithm?",
      answers: {
          a: 'RSA',
          b: 'AES 256-bit',
          c: 'RC6',
          d: 'SHA-256',
          e: 'MD5'
      },
      correctAnswer: 'b'
  },
  {
      question: "What am I? I am an encryption standard chosen as the replacement for 3DES",
      answers: {
          a: 'DES',
          b: 'Rijindael',
          c: 'ISO',
          d: 'NIST'
      },
      correctAnswer: 'b'
  },
  {
      question: "What am I? I am a protocol, set of rules for routing and addressing packets of data so that they can travel accross networks and arrive at the correct destination...",
      answers: {
          a: 'IPsec',
          b: 'IP(Internet Protocol)'
      },
      correctAnswer: 'b'
  },
  {
      question: "What is the maximum recommended number of devices on a subnet?",
      answers: {
          a: 'There isnt one',
          b: '200',
          c: '300',
          d: '400',
          e: '500'
      },
      correctAnswer: 'e'
  },
  {
      question: "What SMTP command means specify the body of the message (To,From and Subject should be the first 3 lines)?",
      answers: {
          a: 'HELO',
          b: 'EHLO',
          c: 'MAIL FROM',
          d: 'RCPT TO',
          e: 'DATA',
          f: 'RSET',
          g: 'QUIT',
          h: 'HELP',
          i: 'VRFY',
          j: 'EXPN',
          k: 'VERB'
      },
      correctAnswer: 'e'
  },
  {
      question: "What does the X.509 standard define?",
      answers: {
          a: 'defines the structure of speed on youtube',
          b: 'defines the structure of a digital certificate',
          c: 'defines the storage on windows',
      },
      correctAnswer: 'b'
  },
  {
      question: " Is a Syn scan (-sS) TCP or UDP?",
      answers: {
          a: 'TCP',
          b: 'UDP'
      },
      correctAnswer: 'a'
  },
  {
      question: "http://user:password@tryhackme.com:[80]/view-room?id=1#task3 what is the component between []",
      answers: {
          a: 'Scheme',
          b: 'User',
          c: 'Host/Domain',
          d: 'Port',
          e: 'Path',
          f: 'Query String',
          g: 'Fragment'
      },
      correctAnswer: 'd'
  },
  {
      question: "Windows uses...",
      answers: {
          a: 'SFTP',
          b: 'TFTP'
      },
      correctAnswer: 'b'
  },
  {
      question: "In what class is the first bit always 0 and the first 8 bits are the network address?",
      answers: {
          a: 'Class A',
          b: 'Class B',
          c: 'Class C',
          d: 'Class D (Multicast)',
          e: 'Class E (Reserved)'
      },
      correctAnswer: 'a'
  },
  {
      question: "To access /etc/shadow file what privileges must you have?",
      answers: {
          a: 'System level privileges',
          b: 'root privileges',
          c: 'Local Privileges'
      },
      correctAnswer: 'b'
  },
  {
      question: "What am I? A __________ is a type of shell in which the target machine communicates back to the attacking machine. The attacking machine has a listening port, on which it receives the connection, resulting in code or command execution being achieved.",
      answers: {
          a: 'Shell',
          b: 'Payload',
          c: 'Forward Shell',
          d: 'Reverse Shell'
      },
      correctAnswer: 'd'
  },
  {
      question: "What method/request would be used to view a news article?",
      answers: {
          a: 'GET',
          b: 'POST',
          c: 'PUT',
          d: 'DELETE'
      },
      correctAnswer: 'a'
  },
  {
      question: "How many unique channels does RDP support?",
      answers: {
          a: 'Upto 65,535 Channels',
          b: '64,000',
          c: '100,000',
          d: '46,000'
      },
      correctAnswer: 'b'
  },
  {
      question: "What does the R in: msfvenom -p cmd/unix/reverse_netcat lhost=[local tun0 ip] lport=4444 R represent?",
      answers: {
          a: 'RPORT',
          b: 'RHOST',
          c: 'Export in RAW format',
      },
      correctAnswer: 'c'
  },
  {
      question: "For ransomware & malware protection, what do you enable in virus and threat protection?",
      answers: {
          a: 'Firewall & network',
          b: 'Microsoft Defender',
          c: 'Real-Time Protection',
          d: 'Password Spray'
      },
      correctAnswer: 'c'
  },
  {
      question: "______ focuses on actually implementing security measures to safeguard systems.",
      answers: {
          a: 'Information Security',
          b: 'Information Assurance'
      },
      correctAnswer: 'a'
  },
  {
      question: " is TFTP TCP or UDP?",
      answers: {
          a: 'TCP',
          b: 'UDP'
      },
      correctAnswer: 'b'
  },
  {
      question: "Where are passwords stored in linux?",
      answers: {
          a: 'SYSTEM file',
          b: '/etc/passwd',
          c: '/etc/shadow',
          d: 'SAM file'
      },
      correctAnswer: 'c'
  },
  {
      question: " In ADDS (Active Directory Domain Service) users are also known as...",
      answers: {
          a: 'Security Policies',
          b: 'Administrators',
          c: 'Users',
          d: 'Security Principles'
      },
      correctAnswer: 'd'
  },
  {
      question: "Does AH (Authentication Header) provide encryption?",
      answers: {
          a: 'Yes',
          b: 'No'
      },
      correctAnswer: 'b'
  },
  {
      question: "What OSI model layer is Telnet on?",
      answers: {
          a: 'Session',
          b: 'Presentation',
          c: 'Applicatiom',
          d: 'Data Link',
          e: 'Physical'
      },
      correctAnswer: 'c'
  },
  {
      question: "What is known as the ISO transport service on top of TCP",
      answers: {
          a: 'IPsec',
          b: 'TKPT',
          c: 'TPKT'
      },
      correctAnswer: 'c'
  },
  {
      question: "What hashes do legacy windows systems use?",
      answers: {
          a: 'SHA-256',
          b: 'SHA-1',
          c: 'LM NTLM',
          d: 'RC4'
      },
      correctAnswer: 'c'
  },
  {
      question: "________ is a key authentication service within AD (Active Directory).",
      answers: {
          a: 'LDAP',
          b: 'Kerberos',
          c: 'Domain Controller',
          d: 'Bitlocker',
          e: 'TPM (Trusted Platform Module)'
      },
      correctAnswer: 'b'
  },
  {
      question: "What is often abreviated to nc?",
      answers: {
          a: 'Netscan',
          b: 'TCP dump',
          c: 'SSH',
          d: 'Telnet',
          e: 'Netcat'
      },
      correctAnswer: 'e'
  },
  {
      question: "What does DNS usually use UDP port 53 for?",
      answers: {
          a: 'DNS Zone Transfer',
          b: 'Lookups'
      },
      correctAnswer: 'b'
  },
  {
      question: "What are hashes used for?",
      answers: {
          a: 'File identification and strong sensitive data i.e passwords',
          b: 'Web Crawlers',
          c: 'Decoration to make the website look fancy'
      },
      correctAnswer: 'a'
  },
  {
      question: "The lack of an ICMP Port Unreachable message is how Nmap discover an open ___ port",
      answers: {
          a: 'TCP',
          b: 'UDP',
          c: '21',
          d: '25'
      },
      correctAnswer: 'b'
  },
  {
      question: "Does SMTP match the physical mail delievery system?",
      answers: {
          a: 'Yes',
          b: 'No'
      },
      correctAnswer: 'a'
  },
  {
      question: "Other than SMTP-USER-ENUM can metasploit be used to enumerate smtp?",
      answers: {
          a: 'Yes',
          b: 'No'
      },
      correctAnswer: 'a'
  },
  {
      question: "True or False: the builtin administrator account in Windows will never be locked out even if account lock out policy is in place",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: "What does collission resistance ensure?",
      answers: {
          a: 'Ensures that a hash function will not produce the same hashed value for two different messages',
          b: 'ensures that an attacker does not collide with the vulnerabilities within that host'
      },
      correctAnswer: 'a'
  },
  {
      question: "What is the acronym for TPM",
      answers: {
          a: 'Trusted Platform Module',
          b: 'Trusted Platform Management',
          c: 'Trusted Protocol Manager',
      },
      correctAnswer: 'a'
  },
  {
      question: "Physical Layer, Data Layer, Network Layer, Transport Layer, Session Layer, Presentation Layer and Application Layer are a of the __ model.",
      answers: {
          a: 'RDP Model',
          b: 'OSI Model',
          c: 'ISO Standard',
          d: 'TCP Model',
          e: "UDP Model"
      },
      correctAnswer: 'b'
  },
  {
      question: "True or False: Diffie-Hellman protocol was developed for key exchange?",
      answers: {
          a: 'True',
          b: 'False, its bitlocker'
      },
      correctAnswer: 'a'
  },
  {
      question: "Client error responses",
      answers: {
          a: '400-499',
          b: '500-599'
      },
      correctAnswer: 'a'
  },
  {
      question: "CeWL and Crunch are tools for generating:",
      answers: {
          a: 'XSS',
          b: 'Wordlists',
          c: 'Attacks',
          d: 'SQL injections'
      },
      correctAnswer: 'b'
  },
  {
      question: "Traffic flows in and out of devices via ports. A ________ is what controls what is and isn't allowed to pass through the ports",
      answers: {
          a: 'Wireshark',
          b: 'Proxy Server',
          c: 'Access Control List',
          d: 'VPN',
          e: 'Firewall'
      },
      correctAnswer: 'e'
  },
  {
      question: " Is 2048 of the accepted key sizes for Advanced Encryption Standard (AES)?",
      answers: {
          a: 'yes',
          b: 'No',
      },
      correctAnswer: 'b'
  },
  {
      question: " The ____ server requires and account name and a password.",
      answers: {
          a: 'IMAP',
          b: 'POP3',
          c: 'SMTP',
      },
      correctAnswer: 'b'
  },
  {
      question: " What does SMTP stand for?",
      answers: {
          a: 'Simple Mail Transfer Port',
          b: 'Simple Mail Transfer Protocol',
          c: 'Service Mail Transfer Protocol',
      },
      correctAnswer: 'c'
  },
  {
      question: "What attack is similar to wordlists but the list is already hashed?",
      answers: {
          a: 'Rainbow attack',
          b: 'dictionary attacks',
          c: 'Brute Force',
          d: 'Guessing'
      },
      correctAnswer: 'a'
  },
  {
      question: "What standard is WPA based on?",
      answers: {
          a: 'NIST',
          b: 'ISO',
          c: 'The International Standard 802.11g '
      },
      correctAnswer: 'c'
  },
  {
      question: "is RDP symmetric or Asymmetric?",
      answers: {
          a: 'Asymmetric',
          b: 'Symmetric'
      },
      correctAnswer: 'a'
  },
  {
      question: "How many hosts does the subnet mask 255.255.0.0 allow?",
      answers: {
          a: '65535 Hosts',
          b: '254 Hosts',
          c: '65534 Hosts',
      },
      correctAnswer: 'c'
  },
  {
      question: "What is the act of exploiting holes in unpatched or poorly-configured software?",
      answers: {
          a: 'SQLi',
          b: 'Trojan Horse',
          c: 'Operating System Attack Type',
          d: 'Shrink-Wrap Code'
      },
      correctAnswer: 'd'
  },
  {
      question: "What restricts access to the computer system's files and folders and demands an online ransom payment to the attacker in order to remove the restrictions?",
      answers: {
          a: 'Malware',
          b: 'Worms',
          c: 'Syn Floods',
          d: 'Ransomware'
      },
      correctAnswer: 'd'
  },
  {
      question: "How are rainbow tables useful?",
      answers: {
          a: 'Slows down password Cracking attack',
          b: 'Speed up a password cracking attack',
          c: 'Prevents a password cracking attack',
      },
      correctAnswer: 'c'
  },
  {
      question: "Basically keeping trracking of everything, like, who's been logging in when are they loggin in and who's data they are accessing",
      answers: {
          a: 'Confidentiality',
          b: 'Integrity',
          c: 'Availability',
          d: 'Authenticity',
          e: 'Auditing and Accountability',
          f: 'Non-Repudiation',
          g: 'reliability'
      },
      correctAnswer: 'e'
  },
  {
      question: "What is the Application, presentation and session layer in the OSI model called in the TCP/IP Conceptual Layers model?",
      answers: {
          a: 'Session',
          b: 'Application',
          c: 'Network Interface',
          d: 'Presentation'
      },
      correctAnswer: 'b'
  },
  {
      question: " What am I? High level statements about protecting information; business rules to safeguard CIA triad; can be applied to users,systems, partners, networks and providers.",
      answers: {
          a: 'Laws',
          b: 'Policies',
          c: 'Compulsory rules',
          d: 'Procedures',
          e: 'Informal Rules'
      },
      correctAnswer: 'b'
  },
  {
      question: " In Windows, what command can be used to list the running services?",
      answers: {
          a: 'ls',
          b: '-ls',
          c: 'SC query'
      },
      correctAnswer: 'c'
  },
  {
      question: "What SMTP command means introduce yourself and request extended mode?",
      answers: {
          a: 'HELO',
          b: 'EHLO',
          c: 'MAIL FROM',
          d: 'RCPT TO',
          e: 'DATA',
          f: 'RSET',
          g: 'QUIT',
          h: 'HELP',
          i: 'VRFY',
          j: 'EXPN',
          k: 'VERB'
      },
      correctAnswer: 'b'
  },
  {
      question: "When are windows updates conducted?",
      answers: {
          a: '2nd Wednesday of each month',
          b: '2nd Tuesday of each month',
          c: '2nd Thursday of each month',
          d: '2nd Monday of each month'
      },
      correctAnswer: 'b'
  },
  {
      question: "What protocol turns an IP address into a MAC address?",
      answers: {
          a: 'ICMP',
          b: 'ARP',
          c: 'IPSec',
          d: 'SNMP'
      },
      correctAnswer: 'b'
  },
  {
      question: "Is social egineering passive or active reconnaissance/footprinting?",
      answers: {
          a: 'Active',
          b: 'Passive'
      },
      correctAnswer: 'a'
  },
  {
      question: "What best describes a cookie",
      answers: {
          a: 'Large piece of data that is stored on your computer',
          b: 'Small piece of data that is stored on your computer',
          c: 'Small piece of data that is not stored on your computer'
      },
      correctAnswer: 'b'
  },
  {
      question: "What methdology conducts password cracking, network mapping, identifies sensitive files, achieve persistence, and lateral movement?",
      answers: {
          a: 'Information Gathering',
          b: 'Enumeration',
          c: 'Exploitation',
          d: 'Post Exploitation',
          e: 'Reporting'
      },
      correctAnswer: 'd'
  },
  {
      question: "Line 1 GET/HTTP/1.1\
      Line 2 Host: tryhackme.com\
      Line 3 User-Agent: Mozila /5.0 Firefox/87.0\
      Line 4 Referer: https: //tryhackme.com/\
      What information can you extract from this example header?",
      answers: {
          a: 'This request is sending the PUT method, the webserver they are requesting is hackthebox, and the browser they are using is Firefox version 87',
          b: 'This response is sending the GET method, the webserver they are responding to is tryhackme.com, and the browser they are using is Firefox version 87',
          c: 'This request is sending the GET method, the webserver they are responding to is tryhackme.com, and the browser they are using is Firefox version 87'
      },
      correctAnswer: 'c'
  },
  {
      question: "What method would be used to create a new user account?",
      answers: {
          a: 'PUT',
          b: 'GET',
          c: 'POST',
          d: 'DELETE'
      },
      correctAnswer: 'c'
  },
  {
      question: "Who am I? What hashes stored user passwords that are fewer than 15 characters long (14 chars plus a parity bit) and all chars were upper cased and there was a split at the 7th character so each half could be cracked independently",
      answers: {
          a: 'MD5',
          b: 'NTLM',
          c: 'LM'
      },
      correctAnswer: 'c'
  },
  {
      question: "__________ is performed by inspecting the responses to VRFY, EXPN, and RCPT TO commands",
      answers: {
          a: 'Enumeration',
          b: 'Exploitation',
          c: 'Post-Exploitation',
      },
      correctAnswer: 'b'
  },
  {
      question: "What am I? Advice on actions given a situation; recommended, not mandatory",
      answers: {
          a: 'Rules',
          b: 'Laws',
          c: 'Procedures',
          d: 'Policies',
          e: 'Guidelines'
      },
      correctAnswer: 'e'
  },
  {
      question: " ICMP type 0, code 8",
      answers: {
          a: 'Source Quench',
          b: 'Destination Unreachable',
          c: 'Echo Request',
          d: 'Redirect',
          e: 'Echo Reply',
          f: 'Time Exceeded'
      },
      correctAnswer: 'e'
  },
  {
      question: "Onesixtyone –c <wordlist> -i <IP list> | tee <outputfile> what does this command do?",
      answers: {
          a: 'footprints',
          b: 'Enumerate Shares',
          c: 'identifies hosts that are using weak community strings',
          d: 'Enumerate Accounts',
          e: 'identifies hosts that are using weak passwords for FTP'
      },
      correctAnswer: 'c'
  },
  {
      question: "The combination of the IP address and a port number make up a _____. i.e 192.168.0.1:8080",
      answers: {
          a: 'Plug',
          b: 'Package',
          c: 'Combination',
          d: 'Joint',
          e: 'Socket',
          f: 'Layer'
      },
      correctAnswer: 'e'
  },
  {
      question: " True or False: Microsoft has defenders to increase and ensure security. Microsoft defenders include; Microsoft defender antivirus and Microsoft defender smartscreen.",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: " What term best describes what happens when two message digests produce the same hash?",
      answers: {
          a: 'Crash',
          b: 'Block',
          c: 'Combined',
          d: 'Collision'
      },
      correctAnswer: 'd'
  },
  {
      question: "Tunnel mode is a valid mode of operation for the ________ protocol",
      answers: {
          a: 'SMB Protocol',
          b: 'NFS Protocol',
          c: 'FTP Protocol',
          d: 'IPsec Protocol'
      },
      correctAnswer: 'd'
  },
  {
      question: "True or False: SMB does not respond to PING?",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: " ____ focuses on risk assessment, mitigation side of things.",
      answers: {
          a: 'Information Assurance',
          b: 'Information Security'
      },
      correctAnswer: 'a'
  },
  {
      question: ". What tool does this? retrieves all of the password hashes that the user account (synced with domain controller) offers.",
      answers: {
          a: 'BurpSuite',
          b: 'Kerbrute',
          c: 'Nmap',
          d: 'SQLmap',
          e: 'secretsdump.py'
      },
      correctAnswer: 'e'
  },
  {
      question: "What attack involves the use of a wordlists to compare against the password?",
      answers: {
          a: 'Dictionary Attacks',
          b: 'Rainbow Tables',
          c: 'Guessing',
          d: 'Brute Force'
      },
      correctAnswer: 'a'
  },
  {
      question: "What does DNS usually use TCP port 53 for?",
      answers: {
          a: 'Zone Transfers',
          b: 'Lookups'
      },
      correctAnswer: 'a'
  },
  {
      question: "What Operating System does SMB usually run on?",
      answers: {
          a: 'UNIX',
          b: 'Linux',
          c: 'Windows'
      },
      correctAnswer: 'c'
  },
  {
      question: "What privillege do you need to have to access the SAM and SYTEM files on windows (Windows\\System32\\config\\)",
      answers: {
          a: 'Local',
          b: 'System Level Privileges',
          c: 'No Privileges, it is accessible to everyone'
      },
      correctAnswer: 'b'
  },
  {
      question: "Enumerating a microsoft IIS 5.0 on a web port might be a sign of what operating system?",
      answers: {
          a: 'Linux',
          b: 'Windows 10',
          c: 'Microsoft Windows Server 2000'
      },
      correctAnswer: 'c'
  },
  {
      question: "What is the acronym for WPA?",
      answers: {
          a: 'There isnt one',
          b: 'Wired Protected Access',
          c: 'WiFi Protected Access'
      },
      correctAnswer: 'c'
  },
  {
      question: "What law does this break? An employee who gains unauthorised access to data they know they are not authorised to access",
      answers: {
          a: 'Computer Misuse Act: Section 1',
          b: 'Computer Misuse Act: Section 2',
          c: 'Computer Misuse Act: Section 3',
          d: 'computer Misuse Act: Section 3ZA',
          e: 'Police and Justice Act(2006)'
      },
      correctAnswer: 'a'
  },
  {
      question: "What layer does SSL, IMAP, MPEG and JPEG operate on?",
      answers: {
          a: '7. Application',
          b: '6. Presentation',
          c: '5. Session',
          d: '4. Transport',
          e: '3. Network',
          f: '2. Data-Link',
          g: '1. Physical'
      },
      correctAnswer: 'b'
  },
  {
      question: "What attack is this? Use of the ACK flag to trick firewall into allowing packets, as many firewalls do not check ACK packets.",
      answers: {
          a: 'ICMP Tunneling',
          b: 'SYN flood',
          c: 'Tiny Fragment',
          d: 'Ack Tunneling',
          e: 'ARP Poisoning'
      },
      correctAnswer: 'd'
  },
  {
      question: "What protocol uses the below commands\nUSER\nPASS\nQUIT\nLIST\nRETR\nDELE\nTOP",
      answers: {
          a: 'IMAP',
          b: 'POP3',
          c: 'SMTP'
      },
      correctAnswer: 'b'
  },
  {
      question: "What layer handles establishment, maintenance, encryption, security, and terminiation of sessions?",
      answers: {
          a: '7. Application',
          b: '6. Presentation',
          c: '5. Session',
          d: '4. Transport',
          e: '3. Network',
          f: '2. Data-Link',
          g: '1. Physical'
      },
      correctAnswer: 'b'
  },
  {
      question: "What is the opposite of confidentiality in the DAD model?",
      answers: {
          a: 'Disclosure',
          b: 'Destruction',
          c: 'Availability'
      },
      correctAnswer: 'a'
  },
  {
      question: "What am I? A hardware-based security chip with a secure crypto-processor that is designed to carry out cryptographic operations. I am tamper resistant and software that is malicious is unable to tamper with the security functions of ________",
      answers: {
          a: 'Bitlocker',
          b: 'TLS/SSL',
          c: 'AES',
          d: 'TPM'
      },
      correctAnswer: 'd'
  },
  {
      question: "In what class is the first bit always 0?",
      answers: {
          a: 'Class A',
          b: 'Class B',
          c: 'Class C',
          d: 'Class D',
          e: 'Class E'
      },
      correctAnswer: 'a'
  },
  {
      question: "What is the acronym for PGP?",
      answers: {
          a: 'Peng Girl Privacy',
          b: 'Privileged Good Privacy',
          c: 'Ping Good Privacy',
          d: 'Pretty Good Privacy'
      },
      correctAnswer: 'd'
  },
  {
      question: " What am I? used to authenticate the identity of a user or process that wants to access a remote system using a particular protocol. The public key is used by both user and the remote server to encrypt messages.",
      answers: {
          a: 'SSH Key Pair',
          b: 'Telnet',
          c: 'RDP(Remote Desktop Protocol)'
      },
      correctAnswer: 'b'
  },
  {
      question: "If port 88 is open what tool can you use to exploit?",
      answers: {
          a: 'Enum4Linux',
          b: 'SMBclient',
          c: 'Kerbrute',
          d: 'Nessus',
          e: 'BurpSuite'
      },
      correctAnswer: 'c'
  },
  {
      question: " What is the difficulty/implications with symmetric encryption?",
      answers: {
          a: 'There is none as it is widely used and implemented',
          b: 'The assurance of secure receipt of the secret key used both for encrypting and decrypting'
      },
      correctAnswer: 'b'
  },
  {
      question: " ___ will synchronise the current inbox, with new mail on the server, downloading anything new",
      answers: {
          a: 'SMTP',
          b: 'IMAP',
          c: 'POP'
      },
      correctAnswer: 'b'
  },
  {
      question: "The destination port information takes up __ bits in a TCP packet",
      answers: {
          a: '13',
          b: '14',
          c: '15',
          d: '16',
          e: '17',
          f: '18',
          g: '20',
      },
      correctAnswer: 'd'
  },
  {
      question: "What should computers who do not have TPM version 1.2 or later be inserted with to ensure security?",
      answers: {
          a: 'Chip',
          b: 'Mouse',
          c: 'Keyboard',
          d: 'PublicKey',
          e: 'USB Startup Key'
      },
      correctAnswer: 'b'
  },
  {
      question: "What does SAM stand for on a Windows System?",
      answers: {
          a: 'LSA Security Account Manager',
          b: 'Security Administrator Managment',
          c: 'Samantha'
      },
      correctAnswer: 'a'
  },
  {
      question: " This is used for getting information from a webserver",
      answers: {
          a: 'PUT',
          b: 'GET',
          c: 'DELETE',
          d: 'POST'
      },
      correctAnswer: 'b'
  },
  {
      question: "What Operating System uses Ip a?",
      answers: {
          a: 'Modern Linux',
          b: 'MAC',
          c: 'Windows',
          d: 'Legacy Linux'
      },
      correctAnswer: 'a'
  },
  {
      question: "What attack involves gaining access to a network and/or computer and then using the same information to gain access to multiple networks and computers that contains desirable information?",
      answers: {
          a: 'XSS',
          b: 'Daisy Chaining/Pivoting',
          c: 'Doxxing',
          d: 'SQLi'
      },
      correctAnswer: 'b'
  },
  {
      question: " What is the acronym for RSA?",
      answers: {
          a: 'Rikers Security America',
          b: 'Rivest Shamir Adleman',
          c: 'Rivest Security Algorithm'
      },
      correctAnswer: 'b'
  },
  {
      question: " What is the acronym for RSA?",
      answers: {
          a: 'Content-Length',
          b: 'Host',
          c: 'User-agent',
          d: 'Content-Type'
      },
      correctAnswer: ''
  },
  {
      question: "What is the default port for POP3",
      answers: {
          a: '110',
          b: '161',
          c: '413',
          d: '25'
      },
      correctAnswer: 'a'
  },
  {
      question: "What OSI layer PDU is identified as Segments?",
      answers: {
          a: '7. Application',
          b: '6. Presentation',
          c: '5. Session',
          d: '4. Transport',
          e: '3. Network',
          f: '2. Data-Link',
          g: '1. Physical'
      },
      correctAnswer: 'd'
  },
  {
      question: "What Layer are TCP/UDP on",
      answers: {
          a: '7. Application',
          b: '6. Presentation',
          c: '5. Session',
          d: '4. Transport',
          e: '3. Network',
          f: '2. Data-Link',
          g: '1. Physical'
      },
      correctAnswer: 'd'
  },
  {
      question: "True or False: The TPM that should be used is version 1.2 or later",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: "What server understands very simple text commands likE HELO, MAIL, RCPT and DATA?",
      answers: {
          a: 'SMTP',
          b: 'TFTP',
          c: 'SNMP',
          d: 'NFS'
      },
      correctAnswer: 'a'
  },
  {
      question: "True or False: Headers are compulsory for a website",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'b'
  },
  {
      question: "What is the opposite of Intergrity in the DAD model?",
      answers: {
          a: 'Disclosure',
          b: 'Destruction',
          c: 'Alteration'
      },
      correctAnswer: 'c'
  },
  {
      question: " FIN --> ACK <--- FIN <---- ACK --->",
      answers: {
          a: 'Pauses a TCP Connection',
          b: 'Begins a TCP connection',
          c: 'Terminates a TCP Connection',
      },
      correctAnswer: 'c'
  },
  {
      question: " How many bits are in an IPv6 address?",
      answers: {
          a: '56',
          b: '62',
          c: '32',
          d: '128',
          e: '196',
          f: '2048'
      },
      correctAnswer: 'd'
  },
  {
      question: " What operating system uses Ipconfig or ipconfig/all?",
      answers: {
          a: 'Mac',
          b: 'Windows',
          c: 'Linux'
      },
      correctAnswer: 'b'
  },
  {
      question: "What command on Windows renews all IP addresses?",
      answers: {
          a: 'Renew',
          b: 'ipconfig',
          c: 'new ipconfig',
          d: 'ipconfig /renew',
          e: 'ipconfig /renew local area'
      },
      correctAnswer: 'd'
  },
  {
      question: "___ and ___ are applications that can specifically be used in order to perform an automated vulnerability scan of a webserver",
      answers: {
          a: 'Nmap and Nessus',
          b: 'SMBClient and Enum4Linux',
          c: 'Nikto and Skipfish'
      },
      correctAnswer: 'c'
  },
  {
      question: "What am I? Sender uses a public key to encrypt the message before sending; recipient can decrypt the message using their related private key",
      answers: {
          a: 'Asymmetric',
          b: 'Symmetric'
      },
      correctAnswer: 'a'
  },
  {
      question: " http://user:password@tryhackme.com:80/view-room?id=1#task3 This is an example of a URL, what is the component highlighted in bold called?",
      answers: {
          a: 'Scheme',
          b: 'User',
          c: 'Host/Domain',
          d: 'Port',
          e: 'Path',
          f: 'Query String',
          g: 'Fragment'
      },
      correctAnswer: ''
  },
  {
      question: "What is the name of the database file on a domain controller that stores passwords and includes the entire Active Directory?",
      answers: {
          a: 'protection Areas',
          b: 'NTDS.dit',
          c: 'SAM file'
      },
      correctAnswer: 'b'
  },
  {
      question: " What am I? a mistake that gives an attacker access to a system or network. It can allow attackers to gain access to data and exfiltrate it?",
      answers: {
          a: 'Threat',
          b: 'Exposure',
          c: 'Vulnerability'
      },
      correctAnswer: 'b'
  },
  {
      question: " The HTTP Host header is used when _ domains exist on a single web server...",
      answers: {
          a: 'One',
          b: 'Two',
          c: 'Three',
          d: 'Four',
          e: 'Five',
      },
      correctAnswer: 'b'
  },
  {
      question: " True or False: the server takes the hash and compares it with the hash in it's database, if its the same that means your password is correct and the server will let you in?",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: "What do the protocol pair consists of in SMTP?",
      answers: {
          a: 'SMTP & FTP',
          b: 'SMTP and SNMP',
          c: 'SMTP and POP(3)/IMAP'
      },
      correctAnswer: 'c'
  },
  {
      question: " Is HEARTBLEED a vulnerability in TLS or OpenSSL?",
      answers: {
          a: 'TLS',
          b: 'OpenSSL'
      },
      correctAnswer: 'b'
  },
  {
      question: "Fill in the blank: MD5 (Message digests) and SHA are popular ______ algorithms...",
      answers: {
          a: 'Encryption',
          b: 'Decryption',
          c: 'Hashing'
      },
      correctAnswer: 'c'
  },
  {
      question: "What are the most prevalent networking threats that is capable of infecting a network within seconds?",
      answers: {
          a: 'Worms',
          b: 'Viruses',
          c: 'Malware',
          d: 'All of the above'
      },
      correctAnswer: 'd'
  },
  {
      question: "Is this a Request or Response Header\nLine 1 GET/HTTP/1.1\nLine 2 Host: tryhackme.com\nLine 3 User-Agent: Mozila /5.0 Firefox/87.0\nLine 4 Referer: https: //tryhackme.com/",
      answers: {
          a: 'Request',
          b: 'Response'
      },
      correctAnswer: 'a'
  },
  {
      question: "What is a stronger encryption algorithm for better user authentication and more sophisticated data encryption, WEP or WPA?",
      answers: {
          a: 'WPA',
          b: 'WEP',
          c: 'Neither'
      },
      correctAnswer: 'a'
  },
  {
      question: "LAMP is a...",
      answers: {
          a: 'Development Hardware Stack',
          b: 'Development Software Stack'
      },
      correctAnswer: 'b'
  },
  {
      question: "What am I? code that will take advantage of a system weakness",
      answers: {
          a: 'Payload',
          b: 'Post-exploitation',
          c: 'Exploit'
      },
      correctAnswer: 'c'
  },
  {
      question: "True or False: CSRF (Cross site request forgery) bulnerability can be used to impersonate a user on a web application?",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: ''
  },
  {
      question: " What does the command lservers do?",
      answers: {
          a: 'list all the domains on a windows system combined with enumerating all the hostnames and IP addresses',
          b: 'Used to obtain a list of systems from a master browser together with details about the version and available services on awindows system'
      },
      correctAnswer: 'b'
  },
  {
      question: "Netstat command shows open ports on computer\n netstat -an means",
      answers: {
          a: 'displays connections in numerical form',
          b: 'displays executables tied to the open port (admin only)'
      },
      correctAnswer: 'a'
  },
  {
      question: "What SNMP version is encrypted protocol, uses user accounts, supports 64 bit counter",
      answers: {
          a: 'SNMPv1',
          b: 'SNMPv2c',
          c: 'SNMPv3'
      },
      correctAnswer: 'b'
  },
  {
      question: "What layer do API's Sockets and WinSock operate on?",
      answers: {
          a: '7. Application',
          b: '6. Presentation',
          c: '5. Session',
          d: '4. Transport',
          e: '3. Network',
          f: '2. Data-Link',
          g: '1. Physical'
      },
      correctAnswer: 'c'
  },
  {
      question: "True or False: FTP and SSH can operate on both Application layer and Presentation layer?",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: "[http]://user:password@tryhackme.com:80/view-room?id=1#task3 This is an example of a URL, what is the component highlighted in brackets called?",
      answers: {
          a: 'Scheme',
          b: 'User',
          c: 'Host/Domain',
          d: 'Port',
          e: 'Path',
          f: 'Query String',
          g: 'Fragment'
      },
      correctAnswer: 'a'
  },
  {
      question: "In most linux systems the non-root/normal user are UID and GID of ____",
      answers: {
          a: '3000',
          b: '1000',
          c: '501',
          d: '502',
          e: '2000',
          f: '500',
          g: '0'
      },
      correctAnswer: 'b'
  },
  {
      question: "What am I? in this cryptography both users have the same key to encrypt and decrypt",
      answers: {
          a: 'Symmetric',
          b: 'Asymmetric',
          c: 'Doesnt Exist'
      },
      correctAnswer: 'a'
  },
  {
      question: " Are Asymmetric (public keys) signed with private keys?",
      answers: {
          a: 'Yes',
          b: 'No'
      },
      correctAnswer: 'a'
  },
  {
      question: "What SMTP command means specify the sender?",
      answers: {
          a: 'HELO',
          b: 'EHLO',
          c: 'MAIL FROM',
          d: 'RCPT TO',
          e: 'DATA',
          f: 'RSET',
          g: 'QUIT',
          h: 'HELP',
          i: 'VRFY',
          j: 'EXPN',
          k: 'VERB'
      },
      correctAnswer: 'c'
  },
  {
      question: " What is the acronym for URL?",
      answers: {
          a: 'Uniform Request locator',
          b: 'Uniform Resource Locator'
      },
      correctAnswer: 'b'
  },
  {
      question: "What is the default port for Telnet?",
      answers: {
          a: '21',
          b: '22',
          c: '23',
          d: '25'
      },
      correctAnswer: 'c'
  },
  {
      question: " How many networks bits does /24 have?",
      answers: {
          a: '8',
          b: '22',
          c: '24',
          d: '32'
      },
      correctAnswer: 'c'
  },
  {
      question: " What is the easiest way to scan for live systems?",
      answers: {
          a: 'Ping Sweep',
          b: 'Nikto',
          c: 'ICMP',
          d: 'Nessus',
          e: 'ARP'
      },
      correctAnswer: 'c'
  },
  {
      question: "Deters the actor from performing the threat i.e Fence, Server Locks, Mantraps, etc",
      answers: {
          a: 'Compensating Control',
          b: 'Detective Control',
          c: 'Preventitive Control',
          d: 'Deterrent Control',
          e: 'Recovery'
      },
      correctAnswer: ''
  },
  {
      question: "What am I? the encryption and decryption keys are different. The encryption key can be used for encryption, not for decryption and vice versa. The encryption key is called the public key and the decryption keys is called the private key.",
      answers: {
          a: 'Symmetric Cryptography',
          b: 'Asymmetric Cryptography'
      },
      correctAnswer: 'b'
  },
  {
      question: "What am I? this attack consists of the exploitation of the web session control mechanism, which is normally managed for a session token. The attack comprises the session token by stealing or predicting a valid session token to gain authorised access to the web server. The session token could be compromised in different ways; such as predictable session token; session sniffing, client-side attacks (XSS, malicious JavaScript codes, trojans), man-in-the-middle attack and man in the browser attack.",
      answers: {
          a: 'SQL injection attack',
          b: 'XSS attack',
          c: 'Session Hijacking'
      },
      correctAnswer: 'c'
  },
  {
      question: " Fundamental Ssecurity concepts:\nThe CIA whole principle is to avoid ________ of the systems through CIA Triad",
      answers: {
          a: 'Theft',
          b: 'Tampering',
          c: 'Disruption',
          d: 'All of the above'
      },
      correctAnswer: 'd'
  },
  {
      question: " __ can be used to remind the server who you are, some personal settings for the website or whether you've been to the website before",
      answers: {
          a: 'HTTP',
          b: 'HTTPS',
          c: 'Cookies'
      },
      correctAnswer: 'c'
  },
  {
      question: "What is the server that runs Active Directory called?",
      answers: {
          a: 'Windows 2003 server',
          b: 'Domain Controller',
          c: 'Azure'
      },
      correctAnswer: 'b'
  },
  {
      question: " What is the true definition of SID?",
      answers: {
          a: 'the SID value is used in the process of RID value creations',
          b: 'Sid is a unique value to represent an object in Active Directory'
      },
      correctAnswer: 'b'
  },
  {
      question: "____ uses 7 principles",
      answers: {
          a: 'Data Protection Act',
          b: 'Computer Misuse Act',
          c: 'GDPR',
          d: 'Human Rights Act'
      },
      correctAnswer: 'c'
  },
  {
      question: "In what class is the first 2 bits always 10 and the first 16 bits are the network address?",
      answers: {
          a: 'CLASS A',
          b: 'CLASS B',
          c: 'CLASS C',
          d: 'CLASS D',
          e: 'CLASS E'
      },
      correctAnswer: 'b'
  },
  {
      question: " Is DES ECB considered the weakest or strongest form of DES?",
      answers: {
          a: 'Strongest',
          b: 'Weakest'
      },
      correctAnswer: 'b'
  },
  {
      question: "CMP type 3, code 0,1,6,7,9,10,13",
      answers: {
          a: 'Echo Request',
          b: 'Source Quench',
          c: 'Time Exceeded',
          d: 'Echo Reply',
          e: 'Redirect',
          f: 'Destination Unreachable'
      },
      correctAnswer: 'f'
  },
  {
      question: "True or False: If an organisation's estate uses Microsoft Windows, you're almost guranteed to find Active Directory",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'b'
  },
  {
      question: "What identifies a new host on the network and assigns an IP address?",
      answers: {
          a: 'Dynamic Host Configuration Protocol',
          b: 'Domain Host Configuration Protocol',
          c: 'Static Address',
          d: 'IPsec'
      },
      correctAnswer: 'a'
  },
  {
      question: "What is the opposite of Availability in the DAD model?",
      answers: {
          a: 'Alteration',
          b: 'Disclosure',
          c: 'Destruction'
      },
      correctAnswer: 'c'
  },
  {
      question: " Communication in RDP is based on...",
      answers: {
          a: 'Multiple Channels',
          b: 'Open Ports',
          c: 'Multiple Connections'
      },
      correctAnswer: 'a'
  },
  {
      question: "What am I? I am a data protection feature that intergrates with the OS. I address the threats of data theft, or exposure from lost, stolen, or inappropriately decommissioned computers.",
      answers: {
          a: 'Data Protection Act',
          b: 'GDPR',
          c: 'Computer Misuse Act',
          d: 'Bitlocker',
          e: 'TPM'
      },
      correctAnswer: 'd'
  },
  {
      question: " IKE is the protocol used to set up a security association in the ______ protocol suite",
      answers: {
          a: 'IPsec',
          b: 'SMB',
          c: 'FTP',
          d: 'IP address'
      },
      correctAnswer: 'a'
  },
  {
      question: "What indicates a poorly configured firewall?",
      answers: {
          a: 'ICMP Type 3, code 1,2,9,11,12',
          b: 'ICMP Type 3, code 14',
          c: 'ICMP Type 3, code 13'
      },
      correctAnswer: 'c'
  },
  {
      question: "Protect the data from modification or deletion by unauthorised parties, and ensuring that when authroised people make changes that shouldn't have been made, the damage can be reversed/undone.",
      answers: {
          a: 'Confidentiality',
          b: 'Integrity',
          c: 'Availability',
          d: 'Authenticity',
          e: 'Accountability',
          f: 'Non-Repudiation',
          g: 'Reliability'
      },
      correctAnswer: 'b'
  },
  {
      question: "Are SHA1 and MD5 hash algorithms secure?",
      answers: {
          a: 'Yes',
          b: 'No'
      },
      correctAnswer: 'b'
  },
  {
      question: " Reconnaissance is the act of gathering evidence about targets. What is the type of reconnaissance that involves direct interaction with the target? i.e make a phone call to the target, using tools like Nessus, Nmap, OpenVAS, Nikto and Metasploit.",
      answers: {
          a: 'Active',
          b: 'Passive'
      },
      correctAnswer: 'a'
  },
  {
      question: "DES has an effective key length of how many bits?",
      answers: {
          a: '56',
          b: '128',
          c: '2048'
      },
      correctAnswer: 'a'
  },
  {
      question: "What prevents users from having access to the control panel and having administrative privilleges in the Active Directory?",
      answers: {
          a: 'Account Lockout Policies',
          b: 'Policies are deployed throughout the network',
          c: 'Bitlocker',
          d: 'TPM'
      },
      correctAnswer: 'b'
  },
  {
      question: "syn ---> syn ack <---- ack ---> is a ___ handshake?",
      answers: {
          a: 'TCP',
          b: 'UDP'
      },
      correctAnswer: 'a'
  },
  {
      question: " What am I? Code that will be executed after an exploit occurs",
      answers: {
          a: 'Exploit',
          b: 'Payload',
          c: 'Auxilliary functions'
      },
      correctAnswer: 'b'
  },
  {
      question: "What am I? An instruction on how to access a resource on the internet",
      answers: {
          a: 'IP address',
          b: 'Proxy Server',
          c: 'URL',
          d: 'WEP',
          e: 'WPA'
      },
      correctAnswer: 'c'
  },
  {
      question: "True or false: the SYSTEM level account is the highest privilege level in the Windows user model?",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: "What is a security feature of OSPF?",
      answers: {
          a: 'It can n authenticate peers using RC5 authentication',
          b: 'It can authenticate peers using MD5 authentication',
          c: 'It can authenticate peers using SSH authentication',
      },
      correctAnswer: 'b'
  },
  {
      question: "What SNMP version uses plaintext protocol, uses community strings, supports 64 bit counters?",
      answers: {
          a: 'SNMPv1',
          b: 'SNMPv2c',
          c: 'SNMPv3'
      },
      correctAnswer: 'b'
  },
  {
      question: "WHat is Port 389?",
      answers: {
          a: 'RDP',
          b: 'RPC',
          c: 'LDAP',
          d: 'IMAP'
      },
      correctAnswer: 'c'
  },
  {
      question: "Does Base64 protect sensitive data?",
      answers: {
          a: 'Yes',
          b: 'No'
      },
      correctAnswer: 'b'
  },
  {
      question: " What is the name of the software that traces an email back to it's point of origin?",
      answers: {
          a: 'Email Header',
          b: 'EmailTrackerPro',
          c: 'DNS Footprint'
      },
      correctAnswer: 'b'
  },
  {
      question: "What should be the recommended mitigation for a missing microsoft patch (or two)?",
      answers: {
          a: 'Change in the patching policy',
          b: 'Keep the patches the same'
      },
      correctAnswer: 'a'
  },
  {
      question: " What header tells the web server which webstie is being requested?",
      answers: {
          a: 'Host',
          b: 'User-Agent',
          c: 'Content-Type',
          d: 'Cookies'
      },
      correctAnswer: 'a'
  },
  {
      question: " http://user:password@tryhackme.com:80/[view-room]?id=1#task3\nThis is an example of a URL, what is the component highlighted with [] called?",
      answers: {
          a: 'Scheme',
          b: 'User',
          c: 'Host/Domain',
          d: 'Port',
          e: 'Path',
          f: 'Query String',
          g: 'Fragment'
      },
      correctAnswer: 'e'
  },
  {
      question: "True or False: The senders private key is generally used to create a digital signature?",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: " True or False: A user can only be apart of a single Organizational Unit at a time",
      answers: {
          a: 'True',
          b: 'False, unlimited'
      },
      correctAnswer: 'a'
  },
  {
      question: " What best defines stateless",
      answers: {
          a: 'Doesnt keep track of your previous requests',
          b: 'it keeps track of your previous requests'
      },
      correctAnswer: 'a'
  },
  {
      question: "Does ESP (Encapsulating security payload) provide encryption and authentication?",
      answers: {
          a: 'Yes',
          b: 'No'
      },
      correctAnswer: 'a'
  },
  {
      question: "Is HTTP Stateless?",
      answers: {
          a: 'Yes',
          b: 'No'
      },
      correctAnswer: 'a'
  },
  {
      question: "What are the two types of cryptography?",
      answers: {
          a: 'Ant and Dec',
          b: 'Symmetric and Asymmetric',
          c: 'Public and Private'
      },
      correctAnswer: 'b'
  },
  {
      question: "What law does this break? DDOS is a cyber-attack in which the perpetrator seeks to make a machine or network resource unavailable to it's intended users by temporarily or indefinetely disrupting services of a host.",
      answers: {
          a: 'Computer Misuse Act: Section 1',
          b: 'Computer Misuse Act: Section 2',
          c: 'Computer Misuse Act: Section 3',
          d: 'computer Misuse Act: Section 3ZA',
          e: 'Police and Justice Act(2006)'
      },
      correctAnswer: 'c'
  },
  {
      question: "What is a shared key encryption?",
      answers: {
          a: 'Uses one key to encode and decode messages',
          b: 'Uses 2 keys to encrypt and decrypt',
          c: 'Uses one key to encrypt and decrypt',
          d: 'Uses 2 keys to encode and decode'
      },
      correctAnswer: 'c'
  },
  {
      question: "You have become concerned that one of your workstations might be infected with a malicious program. What command could help discover the issue?",
      answers: {
          a: 'Netstat -an',
          b: 'Netstat -and',
          c: 'netscan -an'
      },
      correctAnswer: 'a'
  },
  {
      question: "What am I? I Identify and Access management of the entire estate, I hold the keys to the kingdom (hence why I am desirable to attackers). I am the backbon of the corporate world, I simplify the management of devices and users within a corporate environment.",
      answers: {
          a: 'Linux',
          b: 'MacOS',
          c: 'Windows 2003',
          d: 'Kernel',
          e: 'Active Directory'
      },
      correctAnswer: 'e'
  },
  {
      question: "Are machines considered a security principal?",
      answers: {
          a: 'Yes',
          b: 'No'
      },
      correctAnswer: 'a'
  },
  {
      question: "What is the acronym for POP",
      answers: {
          a: 'Post Office Ports',
          b: 'Post office Protocol',
      },
      correctAnswer: 'b'
  },
  {
      question: "What port is the routing protocol RIP (Routing Information Protocol) based on?",
      answers: {
          a: 'TCP/520',
          b: 'UDP/520'
      },
      correctAnswer: 'b'
  },
  {
      question: "What layer consists of end-to-end connections, TCP and UDP?",
      answers: {
          a: '7. Application',
          b: '6. Presentation',
          c: '5. Session',
          d: '4. Transport',
          e: '3. Network',
          f: '2. Data-Link',
          g: '1. Physical'
      },
      correctAnswer: 'd'
  },
  {
      question: "In Linux first user has UID and GID of ___ (Fedora and CentOS)",
      answers: {
          a: '2000',
          b: '514',
          c: '1000',
          d: '501',
          e: '502',
          f: '500',
          g: '0'
      },
      correctAnswer: 'f'
  },
  {
      question: " What atttack am I? permits traversal to directories not in the expected path",
      answers: {
          a: 'MitM attack',
          b: 'Sniffing attack',
          c: 'XSS attack',
          d: 'Directory Traversal Attack'
      },
      correctAnswer: 'd'
  },
  {
      question: "what is the true definition of RID",
      answers: {
          a: 'The RID value is used as proof of concept for windows machines',
          b: 'The RID value is used in the process of SID value creation'
      },
      correctAnswer: 'b'
  },
  {
      question: "What am I? Creates a consistent shadow copy (snapshot or point-in-time copy) of the data that is to be backed up.",
      answers: {
          a: 'USB Startup Key',
          b: 'Bitlocker',
          c: 'TPM',
          d: 'VSS',
          e: 'HMAC'
      },
      correctAnswer: 'd'
  },
  {
      question: "True or False: Payload encryption is a benefit of IPsec?",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: "What protocol comes back with Data/No Response?",
      answers: {
          a: 'SYN',
          b: 'TCP',
          c: 'UDP',
      },
      correctAnswer: 'c'
  },
  {
      question: "What is a one-way mathematical function that does not allow the original value to be calculated from the result?",
      answers: {
          a: 'Hash Function',
          b: 'Encryption Algorithm'
      },
      correctAnswer: 'a'
  },
  {
      question: "In a windows machine what is used to classify users and computers?",
      answers: {
          a: 'Kerberos',
          b: 'LDAP',
          c: 'Domain Admin',
          d: 'Organisational units and Security Groups'
      },
      correctAnswer: 'd'
  },
  {
      question: "What scan conducts: SYN ---> SYN/ACK <--- RST --->",
      answers: {
          a: 'UDP',
          b: 'TCP',
          c: 'SYN'
      },
      correctAnswer: 'c'
  },
  {
      question: "What file in Windows presents as this UserName:SID:LM_Hash:NTLM_Hash:::",
      answers: {
          a: 'SAM file',
          b: 'NTDS.dit'
      },
      correctAnswer: 'a'
  },
  {
      question: " With ________ once you download your email it's stuck on the machine to which you downloaded it. If you want to read your email both on your desktop machine and your laptop (depending on whether you're working in the office or on the road), ______makes life difficult.",
      answers: {
          a: 'IMAP',
          b: 'POP3'
      },
      correctAnswer: 'b'
  },
  {
      question: "What oversees '.co.uk' domain registrations?",
      answers: {
          a: 'ICANN',
          b: 'A',
          c: 'AAAA',
          d: 'CNAME',
          e: 'MX',
          f: 'NS'
      },
      correctAnswer: 'a'
  },
  {
      question: ". _% of corporate networks run off Active Directory",
      answers: {
          a: '100%',
          b: '99%',
          c: '98%',
          d: '97%'
      },
      correctAnswer: 'b'
  },
  {
      question: "Port 445, 139, 88, 389, 3389 are open. What is the likely operating system?",
      answers: {
          a: 'Windows',
          b: 'Linux',
      },
      correctAnswer: 'a'
  },
  {
      question: "True or False: hashes are a long string of letters and numbers generated by hashing algorithms. They take plain text ad make it a hash. They are not reversible, there's no way to decode or decrypt a hash.",
      answers: {
          a: 'True Howveer, some elements are false',
          b: 'False, this is encryption',
          c: 'True',
      },
      correctAnswer: 'c'
  },
  {
      question: "What are the 3 firewall profiles?",
      answers: {
          a: 'Private,Public and domain',
          b: 'Private, Public and ACL',
          c: 'Accessible, no access and medium access',
          d: 'Cloud,Network and infrastucture'
      },
      correctAnswer: 'a'
  },
  {
      question: " Phishing, SSL Hijacking, Encryption Downgrade and Decryption attacks are more likely to take place on what layer of the OSI model?",
      answers: {
          a: '7. Application',
          b: '6. Presentation',
          c: '5. Session',
          d: '4. Transport',
          e: '3. Network',
          f: '2. Data-Link',
          g: '1. Physical'
      },
      correctAnswer: 'b'
  },
  {
      question: " True or False: a Proxy Server is a system or router that provides a gateway between users and the internet",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: "What command for SMTP means introduce yoursel",
      answers: {
          a: 'HELO',
          b: 'EHLO',
          c: 'MAIL FROM',
          d: 'RCPT TO',
          e: 'DATA',
          f: 'RSET',
          g: 'QUIT',
          h: 'HELP',
          i: 'VRFY',
          j: 'EXPN',
          k: 'VERB'
      },
      correctAnswer: 'a'
  },
  {
      question: "What must an organisation balance in order to have a balanced information system?",
      answers: {
          a: 'CIA triad',
          b: 'SC Clearance',
          c: 'bottom to top Managment',
          d: 'Functionality,Security and Usability'
      },
      correctAnswer: 'd'
  },
  {
      question: " Ports 0-1023 are",
      answers: {
          a: 'Well known Ports',
          b: 'Registered Ports',
          c: 'Dynamic Ports'
      },
      correctAnswer: 'a'
  },
  {
      question: " What is the default port for SMTP?",
      answers: {
          a: '25',
          b: '161',
          c: '23',
          d: '22'
      },
      correctAnswer: 'a'
  },
  {
      question: "What am I? a cryptographic output used to verify the authenticity of data. I am a mathematical algorithm routinely used to validate the authenticity and integrity",
      answers: {
          a: 'Prime Numbers',
          b: 'Digital Security',
          c: 'Digital Signature'
      },
      correctAnswer: 'c'
  },
  {
      question: "What are the potential security implications of an attacker being able to modify routing information on a network?",
      answers: {
          a: 'MitM attacks only',
          b: 'Interceptions Only',
          c: 'DoS only',
          d: 'All of the above'
      },
      correctAnswer: 'd'
  },
  {
      question: " IPsec is encoded using...",
      answers: {
          a: 'AES or DES',
          b: 'ESP or AH',
          c: 'SHA1 or SHA-256',
          d: 'MD5'
      },
      correctAnswer: 'b'
  },
  {
      question: " What is classed as a client side attack?",
      answers: {
          a: 'SQLi',
          b: 'XSS'
      },
      correctAnswer: 'b'
  },
  {
      question: "True or False: IDOR (Insecure Direct Object References) is among the top 10 security risks by OWASP?",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: "Of the two internal commands for the SMTP service, what confirms the name of valid users?",
      answers: {
          a: 'DELE',
          b: 'EXPN',
          c: 'HELO',
          d: 'USR',
          e: 'VRFY'
      },
      correctAnswer: 'e'
  },
  {
      question: "What is the default port for FTP",
      answers: {
          a: '21',
          b: '22',
          c: '23',
          d: '25'
      },
      correctAnswer: 'a'
  },
  {
      question: "Public, private, manager and ilmi are",
      answers: {
          a: 'Older Community Strings',
          b: 'Newer Community Strings',
      },
      correctAnswer: 'a'
  },
  {
      question: "Perceived value or worth of a target as seen by the attacker",
      answers: {
          a: 'Threat',
          b: 'Vulnerability',
          c: 'Payload',
          d: 'Explot',
          e: 'Hack Value'
      },
      correctAnswer: 'e'
  },
  {
      question: " What is maintained by MITRE?",
      answers: {
          a: 'IP addresses',
          b: 'CVE',
          c: 'Subnets'
      },
      correctAnswer: 'b'
  },
  {
      question: " Kerbrute, Neo4J, Bloodhound, Impacket, ASREPRoasting are tools used to exploit ________",
      answers: {
          a: 'SMB',
          b: 'System32',
          c: 'NFS',
          d: 'Active Directory',
          e: 'Emails'
      },
      correctAnswer: 'd'
  },
  {
      question: "What is the UID of a root user on a Linux System",
      answers: {
          a: '100',
          b: '0',
          c: '5'
      },
      correctAnswer: 'b'
  },
  {
      question: "Server error responses",
      answers: {
          a: '400-499',
          b: '500-599'
      },
      correctAnswer: 'b'
  },
  {
      question: " True or False: client side data validation is recommended for securing web applications against authenticated users?",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'b'
  },
  {
      question: "What are classed as 'objects' in the active directory?",
      answers: {
          a: 'users, group, machines, printers and shares',
          b: 'Users and groups',
          c: 'Machine, Shares and printers'
      },
      correctAnswer: 'a'
  },
  {
      question: " What IP Address Management does the UK come under?",
      answers: {
          a: 'LACNIC',
          b: 'AfriNIC',
          c: 'ARIN',
          d: 'RIPE',
          e: 'APNIC'
      },
      correctAnswer: 'd'
  },
  {
      question: "What are the three types of Active Defence?",
      answers: {
          a: 'Annoyance,Attribution and Attack',
          b: 'Authenticity,Accountability and Reliability',
          c: 'Confidentiality, integrity and Availability',
          d: 'Auditing and Non-Repudation'
      },
      correctAnswer: 'a'
  },
  {
      question: "What am I? Data is sent in ______. ______ can contain extra information to give to the webserver you're communicating with",
      answers: {
          a: 'HTTP',
          b: 'Cookies',
          c: 'Headers'
      },
      correctAnswer: 'c'
  },
  {
      question: " True or False: POP3 server understands a very simplet set of texr commands?",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: "What is RDP communication encrypted with by default?",
      answers: {
          a: 'Bitlocker',
          b: 'RSAs RC4 Block Cipher',
          c: 'SHA-256'
      },
      correctAnswer: 'b'
  },
  {
      question: "What is the acronym for EISA?",
      answers: {
          a: 'Ethernet Information Security Architecture',
          b: 'Enterprise Information Security Architecture',
          c: 'Environmental information Security Architecture'
      },
      correctAnswer: 'b'
  },
  {
      question: "What security architecture comprises of the following?\nAuthentication credentials stored in SAM file\nFile is located at c:\\windows\\system32\\config\\\nOlder systems use LM hashing. Current uses NTLM v2 (MD5)\nWindows network authentication uses Kerberos",
      answers: {
          a: 'Windows',
          b: 'Linux',
          c: 'MacOS'
      },
      correctAnswer: 'a'
  },
  {
      question: "What am I? an open source test methodology used typically for application testing. It has a famous top 10 of web, mobile and API vulnerabilities which is updated from time to time",
      answers: {
          a: 'OSINT',
          b: 'CHECK',
          c: 'OWASP'
      },
      correctAnswer: 'c'
  },
  {
      question: "Can one-way encrypted passwords be decrypted?",
      answers: {
          a: 'Yes',
          b: 'No'
      },
      correctAnswer: 'b'
  },
  {
      question: "What is CIDR",
      answers: {
          a: 'CIDR is a bitwise, prefix-based standard for the interpretation of subnets',
          b: 'CIDR is a bitwise, prefix-based standard for the interpretation of IP addresses',
          c: 'CIDR is a bitwise, prefix-based standard for the interpretation of routing'
      },
      correctAnswer: 'b'
  },
  {
      question: "What is the port number for RDP?",
      answers: {
          a: '3389',
          b: '445',
          c: '389'
      },
      correctAnswer: 'a'
  },
  {
      question: "What layer are HTTP/FTP/POP3 on?",
      answers: {
          a: '7. Application',
          b: '6. Presentation',
          c: '5. Session',
          d: '4. Transport',
          e: '3. Network',
          f: '2. Data-Link',
          g: '1. Physical'
      },
      correctAnswer: 'e'
  },
  {
      question: " True or False: Users can represent 2 entities in Active Directory Domain Service); people - persons in the organisation that need to access the network, like employees. Also, services - Users can also be services used like IIS or MSSQL. Every service requires a user to run.",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: "Are hackers that are not afraid of going jail or facing any sort of punishment; hack to get the job done.",
      answers: {
          a: 'Black Hat',
          b: 'Hacktivist',
          c: 'Suicide Hackers',
          d: 'State-Sponsored Hackers',
          e: 'CyberTerrorist'
      },
      correctAnswer: 'c'
  },
  {
      question: "What encryption standard has Rijndael replaced?",
      answers: {
          a: 'MD5',
          b: 'RC5',
          c: '3DES',
          d: 'SHA1',
          e: 'Blowfish'
      },
      correctAnswer: 'c'
  },
  {
      question: " ___ encryption is used in IPSec",
      answers: {
          a: 'RSA',
          b: 'Cramer-Shoup',
          c: 'PGP',
          d: 'YAK',
          e: 'GPG'
      },
      correctAnswer: 'd'
  },
  {
      question: "Are MD5 and RC4 secure and recommended?",
      answers: {
          a: 'Yes',
          b: 'No'
      },
      correctAnswer: 'b'
  },
  {
      question: "Hashing algorithms such as MD5 ads are used for...",
      answers: {
          a: 'Confidentiality',
          b: 'Integrity',
          c: 'Availability'
      },
      correctAnswer: 'b'
  },
  {
      question: "True or False: when making a HTTP request you'll find it difficult to view a website properly without a header",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: " How many hosts in a class B network?",
      answers: {
          a: '65534',
          b: '65500',
          c: '65532',
          d: '65535',
          e: '65533'
      },
      correctAnswer: 'a'
  },
  {
      question: "What refers to the assurance of the integrity, availability, confidentiality, and authenticity of information and information systems during usage, processing, storage and transmission of information?",
      answers: {
          a: 'Information Assurance',
          b: 'Locks and Passwords',
          c: 'Information Security'
      },
      correctAnswer: 'a'
  },
  {
      question: "What attack occurs before a vendor knows or is able to patch a flaw?",
      answers: {
          a: 'Zero Day attack',
          b: 'Doxxing',
          c: 'Daisy Chaining/Pivoting',
          d: 'Payload'
      },
      correctAnswer: 'a'
  },
  {
      question: " What am I? I am a group of protocols that are used together to set up encrypted connections between devices. I help keep data sent over public networks secure. I am often used to set up VPNs, and it works by encrypting IP packets along with authenticaticating the source where the packets come from. I am on the data layer and used for routing data.",
      answers: {
          a: 'TLS/SSL',
          b: 'SSH',
          c: 'SHA-256',
          d: 'IPsec'
      },
      correctAnswer: 'd'
  },
  {
      question: " What is the standard for organisations handling credit cards, ATM cards and other POS cards?",
      answers: {
          a: 'displays all listening and active UDP ports on the current machine',
          b: 'displays all listening and active TCP ports on the current machine',
          c: 'displays all listening and active TCP and UDP ports on the current machine'
      },
      correctAnswer: 'a'
  },
  {
      question: "What is the default port for DNS?",
      answers: {
          a: '23',
          b: '53',
          c: '3389',
          d: '389'
      },
      correctAnswer: 'b'
  },
  {
      question: ". What is PHPmyAdmin used to manage?",
      answers: {
          a: 'What is PHPmyAdmin used to manage',
          b: 'Windows OS',
          c: 'Postgres databases',
          d: 'Active Directory',
          e: 'SQL Databases'
      },
      correctAnswer: 'e'
  },
  {
      question: "What layer does ARP and VLAN operate on?",
      answers: {
          a: '7. Application',
          b: '6. Presentation',
          c: '5. Session',
          d: '4. Transport',
          e: '3. Network',
          f: '2. Data-Link',
          g: '1. Physical'
      },
      correctAnswer: '6'
  },
  {
      question: "What is the best choice for a device to filter and cache content from a webpage?",
      answers: {
          a: 'Firewall',
          b: 'Proxy Server'
      },
      correctAnswer: 'b'
  },
  {
      question: "Where is the hash stored once a user creates an account on a website and users password is converted into a hash?",
      answers: {
          a: 'Thin Atmospher',
          b: 'USB Drive',
          c: 'Servers database'
      },
      correctAnswer: 'c'
  },
  {
      question: "What is the acronym for CIDR?",
      answers: {
          a: 'Classless inter-domain routing',
          b: 'Class inter-design request',
          c: 'Classless inter-design response',
          d: 'Classless interacial-dating relationships'
      },
      correctAnswer: 'a'
  },
  {
      question: ". In windows, what acts as the go to intermediary between the hardware and the kernel?",
      answers: {
          a: 'Software Abstraction Layer',
          b: 'Hardware Abstraction Layer'
      },
      correctAnswer: 'b'
  },
  {
      question: " True or False, Brute force attacks can be conducted quicker/faster when knowing the parameters i.e least 7 characters, should contain a special character etc).",
      answers: {
          a: 'False',
          b: 'True'
      },
      correctAnswer: 'b'
  },
  {
      question: " What am I? Combination of policies, processes, procedures, standards, and guidelines to establish thee required level of information security. Designed to ensure the business operates in a state of reduced risk.",
      answers: {
          a: 'Information Assurance',
          b: 'Information Security Managment Program',
          c: 'Active Defense',
          d: 'CVSS'
      },
      correctAnswer: 'b'
  },
  {
      question: "What is the Kerberos ticketing system used for?",
      answers: {
          a: 'Nothing',
          b: 'User for Authentication in a Microsoft Active Directory domain',
          c: 'Used for administraton purposes'
      },
      correctAnswer: 'b'
  },
  {
      question: "What is the acronym for FSMO in AD?",
      answers: {
          a: 'Feeling Sure Microsoft Operating system',
          b: 'File Security Microsoft operations',
          c: 'File Securiy Master Operations',
          d: 'Flexible Single Master Operations',
          e: 'File aZure Microsoft Operating System'
      },
      correctAnswer: 'd'
  },
  {
      question: "What is a misconfiguration of SMB?",
      answers: {
          a: 'There are none',
          b: 'SMB can be configured not to require authentication, which is often called a null session. We can log in to a system with no username of password.',
          c: 'SMB does not have any misconfigurations however, netBIOS TCP/139 does and as a result, SMB is directly impacted.',
          d: 'Windows devices running old versions of SMB are succeptible to a DROWN attack'
      },
      correctAnswer: 'b'
  },
  {
      question: "What are the 2 main types of channels for RDP?",
      answers: {
          a: 'Asymmetric and Symmetric',
          b: 'Static and Dynamic Virtual Channels'
      },
      correctAnswer: 'b'
  },
  {
      question: "What am I? is a weakness that can be exploited to gain unathorised access to, or perform unauthorised actions on a computer system?",
      answers: {
          a: 'Vulnerability',
          b: 'Exposure',
          c: 'Risk'
      },
      correctAnswer: 'a'
  },
  {
      question: " Is this a valid or invalid enumeration technique; send an email to a non-valid address or browse to a non-valid application page to generate a response back that will reveal information about servers",
      answers: {
          a: 'Valid',
          b: 'Invalid',
      },
      correctAnswer: 'a'
  },
  {
      question: "What items can be used to maintain access and ensure future access?",
      answers: {
          a: 'Rootkit,Trojan and Backdoor',
          b: 'Burp Suite',
          c: 'Nessus,Nmap and Nikto',
          d: 'Just RootKits'
      },
      correctAnswer: 'a'
  },
  {
      question: " How many bytes in an IPv4 address?",
      answers: {
          a: '2 bytes',
          b: '4 bytes',
          c: '8 bytes',
          d: '16 bytes'
      },
      correctAnswer: 'b'
  },
  {
      question: " How can you escalate your privelleges to a SYSTEM level account?",
      answers: {
          a: 'SQLi',
          b: 'Exploit weak services running as system',
          c: 'Crack stored password',
          d: 'All of the above'
      },
      correctAnswer: 'd'
  },
  {
      question: "What ports will a domain controller (DC) typicall have open?",
      answers: {
          a: '161,25,334',
          b: '21,22,25,53,23',
          c: '88,389,53,3389,22',
          d: 'It is unknown as there are 65,535 ports'
      },
      correctAnswer: 'c'
  },
  {
      question: "The mount service will then act to connect to the relevant mount daemon using ...",
      answers: {
          a: 'RPC',
          b: 'RDP',
          c: 'SMB'
      },
      correctAnswer: 'a'
  },
  {
      question: "How do you find the encrypted password with a file with one-way encrypted passwords?",
      answers: {
          a: 'It is impossible to do so',
          b: 'Password Cracking attack',
          c: 'Sniffing attack'
      },
      correctAnswer: 'b'
  },
  {
      question: "True or False: Headers are additional bits of data you can send to the webserver when making requests",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: ". ______ exploits a vulnerability",
      answers: {
          a: 'Vulnerability',
          b: 'Threat',
          c: 'Hack Value',
          d: 'Exploit'
      },
      correctAnswer: 'b'
  },
  {
      question: " What methodology identifies versions of software used by systems, identify versions of operating systems and identifies types of devices?",
      answers: {
          a: 'Information Gathering',
          b: 'Enumeration',
          c: 'Exploitation',
          d: 'Post Exploitation',
          e: 'Reporting'
      },
      correctAnswer: 'b'
  },
  {
      question: "How many bits is considered the minimum recommended for a new SSL certificate?",
      answers: {
          a: '2008',
          b: '2004',
          c: '2048',
          d: '128',
          e: '56',
      },
      correctAnswer: 'c'
  },
  {
      question: "What is the acronym for LDAP?",
      answers: {
          a: 'Lightweight Directory Access Protocol',
          b: 'Lightweight Directory Active Protocol',
          c: 'Lightweight Drinkers are Posers'
      },
      correctAnswer: 'a'
  },
  {
      question: "What does restrict anonymous setting of 1 do?",
      answers: {
          a: 'does not allow access without explicit anonymous permissions',
          b: 'prevents the enumerations of SAM accounts and Names'
      },
      correctAnswer: 'b'
  },
  {
      question: "What does the -p in this payload mean: msfvenom -p cmd/unix/reverse_netcat lhost=[local tun0 ip] lport=4444 R",
      answers: {
          a: 'Payload',
          b: 'Protocol',
          c: 'Port'
      },
      correctAnswer: 'a'
  },
  {
      question: "What are the functions SMTP performs?",
      answers: {
          a: "If the outgoing mail can't be delievered it sneds the message back to the sender",
          b: 'it sends outgoing mail',
          c: 'it allows users to read emails'
      },
      correctAnswer: 'b'
  },
  {
      question: "What am I? data encrypted with a public key can only be decrypted with the matching private key",
      answers: {
          a: 'Private Key infrastucture',
          b: 'Public Key Infrastructure'
      },
      correctAnswer: 'b'
  },
  {
      question: "What request am I? used for deleting information/records from a webserver",
      answers: {
          a: 'PUT',
          b: 'DELETE',
          c: 'POST',
          d: 'GET'
      },
      correctAnswer: 'b'
  },
  {
      question: "What is the acronym for WEP?",
      answers: {
          a: 'Wireless Equivalent Privacy',
          b: 'Wired Equivalent Privacy',
          c: 'WiFi Equivalent Privacy'
      },
      correctAnswer: 'b'
  },
  {
      question: ". Identification, Authentication, Authorisation and Accounting work together to manage assets securely. What is the umbrella term for this?",
      answers: {
          a: 'Identity and Access Management',
          b: 'Enterprise Information Security Architecture',
          c: 'NIST',
          d: 'ISO',
          e: 'Information Security Management'
      },
      correctAnswer: 'a'
  },
  {
      question: " True or False: a Token is a unique secret code that is not easily humanly guessable",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: "What is a very popular encoding?",
      answers: {
          a: 'Bitlocker',
          b: 'Base64'
      },
      correctAnswer: 'b'
  },
  {
      question: "What determines the structure and behaviour of organisations information systems through processes, requirements, principles and models?",
      answers: {
          a: 'EISA',
          b: 'CIA Tiad',
          c: 'ISO'
      },
      correctAnswer: 'a'
  },
  {
      question: "How many bit keys does DES contain?",
      answers: {
          a: '65 bit keys',
          b: '56 bit keys',
          c: '566 bit keys',
          d: '565 bit keys',
          e: '5.6 bit keys',
          f: '6.5 bit keys'
      },
      correctAnswer: 'b'
  },
  {
      question: "Mitigates the impact of a manifested threat i.e Backups",
      answers: {
          a: 'Recovery',
          b: 'Deterrent Control',
          c: 'Detective Control',
          d: 'Compensating Control',
          e: 'Preventitive Control'
      },
      correctAnswer: 'a'
  },
  {
      question: "What method/request would be used to update your email address?",
      answers: {
          a: 'GET',
          b: 'DELETE',
          c: 'POST',
          d: 'PUT'
      },
      correctAnswer: 'd'
  },
  {
      question: " What is metasploit framework written in?",
      answers: {
          a: 'Rose',
          b: 'Ruby',
          c: 'Python'
      },
      correctAnswer: 'b'
  },
  {
      question: "What command on Windows renews only the named connection that matches?",
      answers: {
          a: 'Renew Local area/local',
          b: 'ipconfig /renew local area',
          c: 'ipconfig /renew',
          d: 'lcoal.local.renew'
      },
      correctAnswer: 'b'
  },
  {
      question: " What protocol helps users find data about organisations, person's and more. Stores data in LDAP directory and authenticate users to access the directory?",
      answers: {
          a: 'LDAP',
          b: 'Kerberos',
          c: 'RDP'
      },
      correctAnswer: 'a'
  },
  {
      question: "What are the main acts penetration testers should abide by?",
      answers: {
          a: 'Computer Misuse Act',
          b: 'Data Protection Act',
          c: 'GDPR',
          d: 'Police and Justice Act',
          e: 'All of the above'
      },
      correctAnswer: 'e'
  },
  {
      question: " What is required in order to support email services for SMTP?",
      answers: {
          a: 'Protocol Pair',
          b: 'Authentication',
          c: 'Authorisation'
      },
      correctAnswer: 'a'
  },
  {
      question: "True or False: HTTP Requests always end with a blank line to inform the webserver that the request has finished (Line 5)",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: " What is the mitigation against the sslstrip?",
      answers: {
          a: 'Sanitization',
          b: 'Implementing Firewall',
          c: 'Implementing Strict Tansport Security',
          d: 'HMAC'
      },
      correctAnswer: 'c'
  },
  {
      question: " True or False: Asymmetric cryptography is more secure because it uses different keys (public and private keys) however, symmetric cryptography is less secure because it uses the same key therefore if someone takes the keys they can encrypt and decrypt messages you send",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: " What am I? I am a vulnerbaility that affects the integrity and confidentiality of client-side applications code and web application user's data.",
      answers: {
          a: 'SQLi attack',
          b: 'XSS attack'
      },
      correctAnswer: 'b'
  },
  {
      question: " http://[user:password]@tryhackme.com:80/view-room?id=1#task3\nThis is an example of a URL, what is the component highlighted with []called?",
      answers: {
          a: 'Scheme',
          b: 'User',
          c: 'Host/Domain',
          d: 'Port',
          e: 'Path',
          f: 'Query String',
          g: 'Fragment'
      },
      correctAnswer: 'b'
  },
  {
      question: "What layer acts as the communication media and responsible for the actual physical communication between devices?",
      answers: {
          a: '7. Application',
          b: '6. Presentation',
          c: '5. Session',
          d: '4. Transport',
          e: '3. Network',
          f: '2. Data-Link',
          g: '1. Physical'
      },
      correctAnswer: '6'
  },
  {
      question: "What is the maximum number of hosts within a class C subnet?",
      answers: {
          a: '65535',
          b: '254',
          c: '65534'
      },
      correctAnswer: ''
  },
  {
      question: "What is the strongest hashing algorithm?",
      answers: {
          a: 'SHA-256',
          b: 'MD5',
          c: 'Blowfish',
          d: 'AES-256',
          e: 'Diffe-Hellman',
      },
      correctAnswer: 'a'
  },
  {
      question: "What is the default port for HTTP?",
      answers: {
          a: '80',
          b: '88',
          c: '443',
          d: '445',
          e: '161'
      },
      correctAnswer: 'a'
  },
  {
      question: "Hackers that seek to perform malicious activities",
      answers: {
          a: 'Black Hat',
          b: 'White Hat',
          c: 'Suicide Hackers',
          d: 'Gray Hat',
          e: 'Script Kiddie/Skid',
          f: 'Hacktivist',
          g: 'State-Sponsored Hacker',
          h: 'CyberTerrorist'

      },
      correctAnswer: 'a'
  },
  {
      question: "What is the server that runs Active Directory called?",
      answers: {
          a: 'Azure',
          b: 'Apache',
          c: 'Domain Controller'
      },
      correctAnswer: 'c'
  },
  {
      question: "What has four 8 bit numbers?",
      answers: {
          a: 'IPv4',
          b: 'IPv6',
      },
      correctAnswer: 'a'
  },
  {
      question: "True or False: DES and WEP are strong algorithms?",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'b'
  },
  {
      question: "What layer consists of physical structure, coax, fiber, wireless, hubs and repeaters?",
      answers: {
          a: 'Data Link',
          b: 'Physical'
      },
      correctAnswer: 'b'
  },
  {
      question: "What are the components that form a 'sockets'",
      answers: {
          a: 'Data & Packet',
          b: 'Frames & IPsec',
          c: 'IP Address & Port',
          d: 'Port & Ethernet'
      },
      correctAnswer: 'c'
  },
  {
      question: "What is set during initial communication, negotiating of parameters and sequence numbers?",
      answers: {
          a: 'Hash Function',
          b: 'SYN',
          c: 'ACK'
      },
      correctAnswer: 'b'
  },
  {
      question: "What is the acronym for PKI?",
      answers: {
          a: 'Public Key Infrastructure',
          b: 'Private Key Infrastructure'
      },
      correctAnswer: 'b'
  },
  {
      question: "What protection is connection oriented?",
      answers: {
          a: 'TCP',
          b: 'UDP'
      },
      correctAnswer: ''
  },
  {
      question: "What are the most common multifactor authentication methods used?",
      answers: {
          a: 'Something you are (fingerprint) and something you do (android pattern, manual signature)',
          b: 'Something you know (password) and something you have (smart card)',
          c: 'Somewhere you are (geolocation) and something you know (password)'
      },
      correctAnswer: 'b'
  },
  {
      question: "True or False: it is now possible to use the full range of potential network sizes ranging from /0-/32?",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: "Obtaining the unathorised access with the intention of committing theft such as diverting funds. What law does this break?",
      answers: {
          a: 'Computer Misuse Act: Section 1',
          b: 'Computer Misuse Act: Section 2',
          c: 'Computer Misuse Act: Section 3',
          d: 'computer Misuse Act: Section 3ZA',
          e: 'Police and Justice Act(2006)'
      },
      correctAnswer: 'b'
  },
  {
      question: "What layer consists of packets, IP, ICMP, IPSec, IGMP?",
      answers: {
          a: '7. Application',
          b: '6. Presentation',
          c: '5. Session',
          d: '4. Transport',
          e: '3. Network',
          f: '2. Data-Link',
          g: '1. Physical'
      },
      correctAnswer: 'e'
  },
  {
      question: "Which level within nessus is missing from this list: Critical (red), High (dark orange), Medium (brighter orange), Low (yellow) and ________ (blue)",
      answers: {
          a: 'Information',
          b: 'Not Important',
          c: 'Irrelevant'
      },
      correctAnswer: 'a'
  },
  {
      question: "What is the accronym for SHA?",
      answers: {
          a: 'Shakira',
          b: 'Secure Hash Algorithm',
          c: 'Secure HTTP api'
      },
      correctAnswer: 'b'
  },
  {
      question: "What does the cookie value use to prevent password being cleartext string?",
      answers: {
          a: 'HTTPS',
          b: 'TLS and SSL',
          c: 'Token'
      },
      correctAnswer: 'c'
  },
  {
      question: "How many characters is MD5sum made up of?",
      answers: {
          a: '56 Bits',
          b: '23 Characters',
          c: '32 Characters'
      },
      correctAnswer: 'c'
  },
  {
      question: "What protocol has slowly replaced Telnet?",
      answers: {
          a: 'RDP',
          b: 'SSH',
          c: 'FTP',
          d: 'TFTP'
      },
      correctAnswer: 'b'
  },
  {
      question: "This is used for submitting data to the web server and potentially creating new records",
      answers: {
          a: 'POST',
          b: 'PUT',
          c: 'GET',
          d: 'DELETE'
      },
      correctAnswer: 'a'
  },
  {
      question: "is 3DES a asymmetric or symmetric cipher encryption algorithm?",
      answers: {
          a: 'Symmetric',
          b: 'Asymmetric'
      },
      correctAnswer: 'a'
  },
  {
      question: "What layer is X.224 on?",
      answers: {
          a: 'Data Link Layer',
          b: 'Transport Layer',
          c: 'Application Layer',
          d: 'Session Layer'
      },
      correctAnswer: 'b'
  },
  {
      question: " Can a computed hash be reversed?",
      answers: {
          a: 'Yes',
          b: 'No'
      },
      correctAnswer: 'b'
  },
  {
      question: "What hashes are stored by default on a Windows 2003 system?",
      answers: {
          a: 'SHA-256',
          b: 'LM and NTLM',
          c: 'RC4'
      },
      correctAnswer: 'b'
  },
  {
      question: "When a HTTP server responds, the first line always contains a...",
      answers: {
          a: 'content-length',
          b: 'content-type',
          c: 'User-Agent',
          d: 'host',
          e: 'Status Code'
      },
      correctAnswer: 'e'
  },
  {
      question: "What does restrict anonymous setting of 2 on a windows system do?",
      answers: {
          a: 'does not allow access without explicit anonymous permissions',
          b: 'Prevents the enumeration of SAM accounts and names'
      },
      correctAnswer: 'a'
  },
  {
      question: "What maintains service names and transport protocol port number registry which lists all port number reservations?",
      answers: {
          a: 'IANA (Internet Assigned Numbers Authority) ',
          b: 'ISO (International Organisation for Standardisation)',
          c: 'DHCP (Dynamic Host Configuration Protocol)',
          d: 'Enterprise Information Security Architecture'
      },
      correctAnswer: 'a'
  },
  {
      question: "What port is SYSLOG (UDP)?",
      answers: {
          a: '161',
          b: '25',
          c: '512',
          d: '514'
      },
      correctAnswer: 'd'
  },
  {
      question: "What is the acronym for IMAP?",
      answers: {
          a: 'Internet Message Access Protocol',
          b: 'Information Message Access Protcol',
          c: 'nternet Mail Access Protocol'
      },
      correctAnswer: 'a'
  },
  {
      question: "What am I? an internet organisation residing in Europe. My objective is to ensure the administrative and technical coordination necessary to enable the operation of the internet.",
      answers: {
          a: 'IPsec',
          b: 'Internet Protocol',
          c: 'RIPE',
          d: 'CIDR',
          e: 'ISO 27001'
      },
      correctAnswer: 'c'
  },
  {
      question: ". What tool in linux can be used to generate an SSH key pair",
      answers: {
          a: 'NMAP',
          b: 'BurpSuite',
          c: 'SSH-create',
          d: 'SSH-keygen'
      },
      correctAnswer: 'd'
  },
  {
      question: "Improperly configuring a service or application is called ________",
      answers: {
          a: 'Buffer Overflow',
          b: 'Missing Patches',
          c: 'Default Installation',
          d: 'Misconfiguration'
      },
      correctAnswer: 'd'
  },
  {
      question: " What layer is data translated, compressed, encoded, encrypted (if enabled) in such a way that the receiving application can understand and can be transported over the network?",
      answers: {
          a: '7. Application',
          b: '6. Presentation',
          c: '5. Session',
          d: '4. Transport',
          e: '3. Network',
          f: '2. Data-Link',
          g: '1. Physical'
      },
      correctAnswer: 'b'
  },
  {
      question: "What am I? set of details and steps to accomplish a goal; instructions for implementation.",
      answers: {
          a: 'Procedures',
          b: 'Policies',
          c: 'Rules',
          d: 'Laws',
          e: 'Guidelines'
      },
      correctAnswer: 'a'
  },
  {
      question: "You are a web developer and you need to choose between RC4,RC5 and RC6. What cipher is the more secure one to choose?",
      answers: {
          a: 'RC6',
          b: 'RC5',
          c: 'RC4'
      },
      correctAnswer: 'a'
  },
  {
      question: "What is the blocksize of the AES encryption cipher? (diskspace/data storage)",
      answers: {
          a: '128 bits',
          b: '64 bits',
          c: '2048 bits',
          d: '196 bits'
      },
      correctAnswer: 'a'
  },
  {
      question: "How many bytes in an IPv6 address?",
      answers: {
          a: '8 bytes',
          b: '12 bytes',
          c: '16 bytes',
          d: '32 bytes',
          e: '4 bytes'
      },
      correctAnswer: 'c'
  },
  {
      question: "Provides alternative fixed for any of the control functions",
      answers: {
          a: 'Preventive control',
          b: 'Recovery',
          c: 'Deterent Control',
          d: 'Detective Control',
          e: 'Compensating Control'
      },
      correctAnswer: 'e'
  },
  {
      question: "What is the Data Link and Physical layer of the OSI model called in the TCP/IP Conceptual Layers model?",
      answers: {
          a: 'Physical',
          b: 'Network Interface',
          c: 'Network Layer',
          d: 'Physical x Datalink'
      },
      correctAnswer: ''
  },
  {
      question: "What is the first step in the SMTP process?",
      answers: {
          a: 'communicate with the wider internet',
          b: 'communicates with POP3 and IMAP server',
          c: 'SMTP handshake',
          d: 'Sends email to the recepient'
      },
      correctAnswer: 'c'
  },
  {
      question: "Without DHCP it is required to set interface details such as?",
      answers: {
          a: 'IP address',
          b: 'Default Gateway',
          c: 'Network Mask',
          d: 'DNS server',
          e: 'All of the above'
      },
      correctAnswer: 'e'
  },
  {
      question: "What layer does ARP (Address Resolution Protocol) operate on?",
      answers: {
          a: 'layer 2',
          b: 'Layer 1',
          c: 'Layer 7',
          d: 'Layer 6'
      },
      correctAnswer: 'a'
  },
  {
      question: "Linux uses...",
      answers: {
          a: 'TFTP',
          b: 'SFTP'
      },
      correctAnswer: 'b'
  },
  {
      question: "What attack am I? I am a malware that misleads user of it's true intent. I'm a type of malware that disguises itself as legitimate code or software",
      answers: {
          a: 'SQLi',
          b: 'Trojan Horse',
          c: 'XSS'
      },
      correctAnswer: 'b'
  },
  {
      question: "What is the name of the archive web service for finding information from historical web pages?",
      answers: {
          a: 'Historical Machine',
          b: 'Wayback Machine',
          c: 'Throwback Machine',
          d: 'Legacy Machine'
      },
      correctAnswer: 'b'
  },
  {
      question: "What cipher uses a block cipher to generate a key stream that can be used as a stream cipher?",
      answers: {
          a: 'Rivest Cipher',
          b: 'CFB cipher'
      },
      correctAnswer: 'b'
  },
  {
      question: "What is the default port for SSH?",
      answers: {
          a: '21',
          b: '22',
          c: '23',
          d: '25'
      },
      correctAnswer: 'b'
  },
  {
      question: "What is the most likely outcome if on a windows 2003 SP1 server you attempt a MS08-067 exploit",
      answers: {
          a: 'The session will not quit and everything will remain the same',
          b: 'A shell will form but a crash is not likely to occur since the server is so outdated and has the EXITFUNC feature',
          c: 'You will get a shell but regardless of the EXITFUNC setting the server will crash when you quit the session',
      },
      correctAnswer: 'c'
  },
  {
      question: "What explains 'does not require pre-authentication' the best?",
      answers: {
          a: 'Account does not need to provide valid identification before requesting a Kerberos ticket on the user account',
          b: 'Account does need to provide valid identification before requesting a Kerberos ticket on the user account'
      },
      correctAnswer: 'a'
  },
  {
      question: "Is the SHA-256 algorithm reversible encryption?",
      answers: {
          a: 'Yes',
          b: 'No'
      },
      correctAnswer: 'b'
  },
  {
      question: "Password hashes are boot locked (unless you have system level privileges you cannot access them) in what operating system?",
      answers: {
          a: 'Linux',
          b: 'Windows',
          c: 'Mac'
      },
      correctAnswer: 'b'
  },
  {
      question: "What component of an operating system is responsible for controlling the execution of user programs and operations of I/O devices?",
      answers: {
          a: 'System32',
          b: '%System%',
          c: 'The Control Program'
      },
      correctAnswer: 'c'
  },
  {
      question: "True or False: 'when targetting Windows OS, version information is usually not included as part of the Nmap scan results'",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: "What am I? A _______ can simply be described as a piece of code or program which can be used to gain code or command execution on a device",
      answers: {
          a: 'MSFVENOM',
          b: 'Payload',
          c: 'Telnet',
          d: 'Shell'
      },
      correctAnswer: 'd'
  },
  {
      question: "What type of cryptography is AES, DES, IDEA, Blowfish, RC4,5,6?",
      answers: {
          a: 'Organisational Units',
          b: 'Groups',
          c: 'Users',
          d: 'Administrators'
      },
      correctAnswer: 'a'
  },
  {
      question: "What are the objects organised in to classify users and machine?",
      answers: {
          a: 'Organisational Units',
          b: 'Groups',
          c: 'Users',
          d: 'Administrators'
      },
      correctAnswer: 'a'
  },
  {
      question: "What does Microsoft defender Smartscreen do?",
      answers: {
          a: 'Protects against phishing or malware websites and applications, and the downloading of potential malicious files. Checks for unrecognised apps and files from the web',
          b: 'Checks files, folders, running programs on your hard disk, etc for viruses and threats',
      },
      correctAnswer: 'a'
  },
  {
      question: "TPM (Trusted Platform Module) is a hardware component installed in new devices by computer manufacturers. It works with ______ to help protect user data and to ensure that a computer has not been tampered with",
      answers: {
          a: 'TLS/SSL',
          b: 'RSA',
          c: 'RC6',
          d: 'Bitlocker'
      },
      correctAnswer: 'd'
  },
  {
      question: " Systems, access channels, and authentication mechanisms must all be working properly for the information they provide and protect to be available when needed.",
      answers: {
          a: 'Confidentiality',
          b: 'Integrity',
          c: 'Availability',
          d: 'Authenticity',
          e: 'Accountability',
          f: 'Non-Repudiation',
          g: 'Reliability'
      },
      correctAnswer: 'c'
  },
  {
      question: " What methodology exploits protocol weaknesses such as FTP or SNMP for common vulnerabilities, exploits OS vulnerabilities such as MS17-010 (Eternal Blue) and exploits software vulnerabilities such as Adobe, php etc?",
      answers: {
          a: 'Information Gathering',
          b: 'Enumeration',
          c: 'Exploitation',
          d: 'Post exploitation',
          e: 'Reporting'
      },
      correctAnswer: 'c'
  },
  {
      question: "Acronym for CVE?",
      answers: {
          a: 'Communication Vulnerabilities and Exposures',
          b: 'Common Vulnerabilities Exposures',
          c: 'Common Vulnerability Exploits'
      },
      correctAnswer: 'b'
  },
  {
      question: "What command do you use to view an arp cache to what computer the local machine knows about?",
      answers: {
          a: 'arp -a',
          b: 'arp -b',
          c: 'arp -c',
          d: 'arp -d'
      },
      correctAnswer: 'a'
  },
  {
      question: "What layers do PC, Phone, Server, Host Firewall, NIPS, HIPS, WAF and Gateways operate on?",
      answers: {
          a: '7. Application',
          b: '6. Presentation',
          c: '5. Session',
          d: '4. Transport',
          e: '3. Network',
          f: '2. Data-Link',
          g: '1. Physical'
      },
      correctAnswer: 'a'
  },
  {
      question: " _________ is the assurance that someone cannont deny the validity of something. ________ is a legal concept that is widely used in information security and refers to a service, which provides proof of the origin of data and the integrity of the data",
      answers: {
          a: 'Confidentiality',
          b: 'Integrity',
          c: 'Availability',
          d: 'Authenticity',
          e: 'Auditing and Accountability',
          f: 'Non-Repudation',
          g: 'Reliability'
      },
      correctAnswer: 'f'
  },
  {
      question: " Publishing PII (Personal Identifiable Information) about an individual usually with a malicious intent",
      answers: {
          a: 'Doxxing',
          b: 'Daisy Chaining/Pivoting',
          c: 'Zero-Day attack',
          d: 'Payload'
      },
      correctAnswer: 'a'
  },
  {
      question: "This service acts as a catalogue that holds the information of all of the 'objects' that exist on your network",
      answers: {
          a: 'System32',
          b: 'LDAP',
          c: 'Kerberos',
          d: 'Active Directory Domain Service'
      },
      correctAnswer: 'd'
  },
  {
      question: "What helps prevent DNS poisoning by encrypting records?",
      answers: {
          a: 'DNDSEC',
          b: 'Secure Host',
          c: 'DNSSEC'
      },
      correctAnswer: 'c'
  },
  {
      question: " True or False: LDAP enables organisations to store, manage, and secure information about the organisation, it users and assets like usernames and passwords.",
      answers: {
          a: 'False',
          b: 'True'
      },
      correctAnswer: 'b'
  },
  {
      question: "What is a security implication of bi-directional trust relationship between domain A and B?",
      answers: {
          a: 'If domain administrator account on domain A is broken into then the domain administrator account domain B is also broken into',
          b: 'If domain A is broken into then the domain administrator account on domain B is not broken into'
      },
      correctAnswer: 'a'
  },
  {
      question: "Is SHA-256 Secure ",
      answers: {
          a: 'yes',
          b: 'No'
      },
      correctAnswer: 'b'
  },
  {
      question: "What is the default port for modern SMB?",
      answers: {
          a: '443',
          b: '110',
          c: '139',
          d: '445'
      },
      correctAnswer: 'd'
  },
  {
      question: "What is the default port for NetBIOS/old SMB?",
      answers: {
          a: '445',
          b: '139',
          c: '389',
          d: '3389'
      },
      correctAnswer: 'b'
  },
  {
      question: "What is not recommended to brute force credentials?",
      answers: {
          a: 'Cause a Crash',
          b: 'Password Spray',
          c: 'Account Lockout Policies'
      },
      correctAnswer: 'c'
  },
  {
      question: " Netstat command shows open ports on computer\nnetstat -b means...",
      answers: {
          a: 'displays executables tied to the open port (admin only',
          b: 'displays connections in numerical form'
      },
      correctAnswer: 'a'
  },
  {
      question: "-u url, -r request, -p parameter are flags from what tool?",
      answers: {
          a: 'Nmap',
          b: 'Nikto',
          c: 'SQLmap',
          d: 'SMBclient'
      },
      correctAnswer: 'c'
  },
  {
      question: "What does a datagram comprise of?",
      answers: {
          a: 'Header',
          b: 'IP addresses of destination and source',
          c: 'Data',
          d: 'All of the Above'
      },
      correctAnswer: 'd'
  },
  {
      question: "What port does LDAP operate on?",
      answers: {
          a: '88',
          b: '445',
          c: '389',
          d: '600'
      },
      correctAnswer: 'c'
  },
  {
      question: "When will an ICMP Type 3 port unreachable response be returned?",
      answers: {
          a: 'if a UDP port is closed',
          b: 'if a UDP port is open',
          c: 'if a TCP port is closed',
          d: 'if a TCP Port is open'
      },
      correctAnswer: 'a'
  },
  {
      question: "True or false: payload of an ICMP message can be anything; RFC never set what it was supposed to be. Allows for covert channeles",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: " What is the practise of detecting and preventing data breaches, exfiltration, or unwanted destruction of sensitive data. Organisations use it to protect and secure their data and comply with regulations?",
      answers: {
          a: 'Identity',
          b: 'ISO',
          c: 'Data Loss Prevention'
      },
      correctAnswer: 'c'
  },
  {
      question: "Is IDEA generally safe and secure to use?",
      answers: {
          a: 'Yes',
          b: 'No'
      },
      correctAnswer: 'a'
  },
  {
      question: " Is RSA used by legacy or modern computers to encrypt and decrypt messages?",
      answers: {
          a: 'Legacy Computers',
          b: 'Modern Computers'
      },
      correctAnswer: 'b'
  },
  {
      question: "Does RSA involve a public and private key?",
      answers: {
          a: 'Yes',
          b: 'No'
      },
      correctAnswer: 'a'
  },
  {
      question: "What does boot locked mean?",
      answers: {
          a: 'Unless you have system level privileges you cannont access password hashes',
          b: 'Unless you have system level privileges you can access password hashes but you just cant crack them',
      },
      correctAnswer: 'a'
  },
  {
      question: "True or False: IPv6 is increasingly being used due to the sheer number of smart devices in existence and is made up of a 128-bit number (eight 4-character hex values) i.e FE80:CD01:8BDE:211E:792C:1132:BA83:032C",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: "What layers's PDU is identified as Data?",
      answers: {
          a: '7. Application',
          b: '6. Presentation',
          c: '5. Session',
          d: '4. Transport',
          e: '3. Network',
          f: '2. Data-Link',
          g: '1. Physical'
      },
      correctAnswer: 'a'
  },
  {
      question: "What is the default protocol for authentication in Windows?",
      answers: {
          a: 'LDAP',
          b: 'Kerberos',
          c: 'SMB',
          d: 'Active Directory',
          e: 'SSH'
      },
      correctAnswer: 'b'
  },
  {
      question: "What layer does the syntax layer operate on?",
      answers: {
          a: '7. Application',
          b: '6. Presentation',
          c: '5. Session',
          d: '4. Transport',
          e: '3. Network',
          f: '2. Data-Link',
          g: '1. Physical'
      },
      correctAnswer: 'b'
  },
  {
      question: "SET Cookie: ARPT=ITOUQOwebserver1ckuqw is something to look out for when enumerating...",
      answers: {
          a: 'SMTP',
          b: 'Telnet',
          c: 'NFS',
          d: 'Cisco IronPort',
          e: 'HTTP'
      },
      correctAnswer: 'd'
  },
  {
      question: "What is the international standard that has been prepared to provide requirements for establishing, implementing, maintaining and continually improving an information security management system?",
      answers: {
          a: 'NIST (National Institute of Standards and Technology) ',
          b: 'ISO 27001 (International Organisation for Standardisation)',
          c: 'PCI-DSS (Payment Card Industry Data Security Standard)'
      },
      correctAnswer: 'b'
  },
  {
      question: " True or False: SSH 1.0 and 1.99 have significant flaws and should not be used",
      answers: {
          a: 'True',
          b: 'False',
      },
      correctAnswer: 'a'
  },
  {
      question: "What is the default privilege of an IIS 4 server?",
      answers: {
          a: 'Admin',
          b: 'Local System',
          c: 'IUSER_Computername'
      },
      correctAnswer: 'b'
  },
  {
      question: "'Prove you are the legitimate user'\ni.e something you know (password)\nSomething you have (Smart Card)\nSomething you are (Fingerprint)\nSomething you do (android pattern, manual signature)\nSomewhere you are (geolocation)\n What does this come under",
      answers: {
          a: 'Authorisation',
          b: 'Account',
          c: 'Identification',
          d: 'Authentication'
      },
      correctAnswer: 'd'
  },
  {
      question: "What does LAMP stand for?",
      answers: {
          a: 'Linux Apache MySQL PHP',
          b: 'Linux Apache Microsoft PHP',
          c: 'Linux Apple Microsoft PHP',
      },
      correctAnswer: 'a'
  },
  {
      question: "What layer in the OSI model does TLS and SSL operate on?",
      answers: {
          a: '7. Application',
          b: '6. Presentation',
          c: '5. Session',
          d: '4. Transport',
          e: '3. Network',
          f: '2. Data-Link',
          g: '1. Physical'
      },
      correctAnswer: 'b'
  },
  {
      question: " Failure to change settings in an application that come by default is called __________",
      answers: {
          a: 'Default Installation',
          b: 'Operating System Flaws',
          c: 'Misconfiguration',
          d: 'Missing Patches'
      },
      correctAnswer: 'a'
  },
  {
      question: "Virus & threat protection, firewall & network protection, app & browser control and device security are _______ in Windows security",
      answers: {
          a: 'Athentication Areas',
          b: 'Protection Areas',
          c: 'Access Areas'
      },
      correctAnswer: 'b'
  },
  {
      question: "http://user:password@tryhackme.com:80/view-room?[id=1]#task3\nThis is an example of a URL, what is the component highlighted with [] called?",
      answers: {
          a: 'Scheme',
          b: 'User',
          c: 'Host/Domain',
          d: 'Port',
          e: 'Path',
          f: 'Query String',
          g: 'Fragment'
      },
      correctAnswer: 'f'
  },
  {
      question: " If a system encrypts data prior to transmitting it over a network, and the system on the other end of the transmission media decrypts it using a different key, then an ________ encryption algorithm is used",
      answers: {
          a: 'Asymmetric',
          b: 'Symmetric'
      },
      correctAnswer: 'a'
  },
  {
      question: "True or False: TLS and SSL is used to encrypt data as it travels over a network?",
      answers: {
          a: 'True',
          b: 'False',
      },
      correctAnswer: 'a'
  },
  {
      question: "What operating system is RDP on?",
      answers: {
          a: 'Windows',
          b: 'Linux',
          c: 'Mac'
      },
      correctAnswer: 'a'
  },
  {
      question: " The machine account is the computers name followed by a what sign? i.e DC01_",
      answers: {
          a: '//',
          b: '%',
          c: '$',
          d: '£'
      },
      correctAnswer: 'c'
  },
  {
      question: "Should SSH 1.0 and 1.99 be used?",
      answers: {
          a: 'yes',
          b: 'No'
      },
      correctAnswer: 'b'
  },
  {
      question: "What am I? Supplementary tools and commands that can be used for enumeration among other actions",
      answers: {
          a: 'Auxiliary functions',
          b: 'Exploit',
          c: 'Post-exploitation'
      },
      correctAnswer: 'a'
  },
  {
      question: "Is RC5 Asymmetric or Symmetric?",
      answers: {
          a: 'Asymmetrical algorithm (public and private key)',
          b: 'Symmetrical algorithm (Same keys)'
      },
      correctAnswer: 'b'
  },
  {
      question: "What device provides outbound access to systems not in the current network?",
      answers: {
          a: 'DNS Server',
          b: 'IP address',
          c: 'Router',
          d: 'MAC address',
          e: 'Default Gateway'
      },
      correctAnswer: 'e'
  },
  {
      question: "True or False: SSH v1.99 supports v1.0 and v2.0 and this can lead to v1.0 being used which is known to vulnerable attacks",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: "Are the machine accounts users, admin or local administrators?",
      answers: {
          a: 'Users',
          b: 'Local Administrators',
          c: 'Admin'
      },
      correctAnswer: 'b'
  },
  {
      question: "Which group normally administrates all computers and resources in a domain?",
      answers: {
          a: 'Organisational Units',
          b: 'Email Headers',
          c: 'DNS SOA Record'
      },
      correctAnswer: 'b'
  },
  {
      question: "What snmp version is a plaintext protocol, uses community strings, only supports 32 bit counters?",
      answers: {
          a: 'SNMPv1',
          b: 'SNMPv2c',
          c: 'SNMPv3'
      },
      correctAnswer: 'a'
  },
  {
      question: "What is the opposite of the CIA triad?",
      answers: {
          a: 'IAD',
          b: 'IAC',
          c: 'AIC',
          d: 'DAD'
      },
      correctAnswer: 'd'
  },
  {
      question: "Unskilled idividual who uses malicious scripts or programs, such as a web shell, developed by others to attack computer systems and networks and deface websites.",
      answers: {
          a: 'Hacktivist',
          b: 'White Hat',
          c: 'Black Hat',
          d: 'Suicide Hackers',
          e: 'State-Spondored Hacker',
          f: 'Gray Hat',
          g: 'CyberTerrorist',
          h: 'Script Kiddie/Skiddies'
      },
      correctAnswer: 'h'
  },
  {
      question: " Is RC6 (Rivest Cipher) secure?",
      answers: {
          a: 'Yes',
          b: 'No',
      },
      correctAnswer: 'a'
  },
  {
      question: "RSA (Rivest, Shamir & Adleman), Diffie-Hellman, Elliptic Curv, RSA Cramer-Shoup, YAK used in IPsec, PGP, GPG, TLS/SSL and SSH are a type of _________ algorithm",
      answers: {
          a: 'Asymmetric',
          b: 'Symmetric'
      },
      correctAnswer: 'a'
  },
  {
      question: "The lack of what, means that all Telnet communication is in plaintext?",
      answers: {
          a: 'Encryption',
          b: 'Connection'
      },
      correctAnswer: 'a'
  },
  {
      question: "What are the valid key lengths for the AES encryption cipher?",
      answers: {
          a: '2048,128,192',
          b: '56,128,192',
          c: '128,192,256'
      },
      correctAnswer: 'c'
  },
  {
      question: "Redirection messages",
      answers: {
          a: '100-199',
          b: '200-299',
          c: '300-399',
          d: '400-499'
      },
      correctAnswer: 'c'
  },
  {
      question: "Motivated by religious or political beliefs to create fear or disruption",
      answers: {
          a: 'Hacktivist',
          b: 'White Hat',
          c: 'Black Hat',
          d: 'Suicide Hackers',
          e: 'State-Spondored Hacker',
          f: 'Gray Hat',
          g: 'CyberTerrorist',
          h: 'Script Kiddie/Skiddies'
      },
      correctAnswer: 'g'
  },
  {
      question: "What does LSA stand for on a Windows System?",
      answers: {
          a: 'Local Security Accounts',
          b: 'Local Security Authority',
          c: 'Local Security Administration',
      },
      correctAnswer: 'b'
  },
  {
      question: "Hackers that perform good or bad activities but do not have the permission of the organisation they are hacking against",
      answers: {
          a: 'Hacktivist',
          b: 'White Hat',
          c: 'Black Hat',
          d: 'Suicide Hackers',
          e: 'State-Spondored Hacker',
          f: 'Gray Hat',
          g: 'CyberTerrorist',
          h: 'Script Kiddie/Skiddies'
      },
      correctAnswer: 'f'
  },
  {
      question: " What attack looks for users without Kerberos pre-authentication required attribute (DONT_REQ_PREAUTH)?",
      answers: {
          a: 'SQLi',
          b: 'Trojan',
          c: 'ASREPRoasting',
          d: 'Kerbrute'
      },
      correctAnswer: 'c'
  },
  {
      question: "what OS uses ifconfig",
      answers: {
          a: 'Mac',
          b: 'Legacy Linux',
          c: 'Modern Linux',
          d: 'Windows'
      },
      correctAnswer: 'b'
  },
  {
      question: "What is the best practise method of practising against SQL injection attacks?",
      answers: {
          a: 'Firewall',
          b: 'Parameterised Statements/Prepared statements',
          c: 'Implement Whitelisting for file names and locations'
      },
      correctAnswer: 'b'
  },
  {
      question: "Gathering evidence about targets is called Reconnaissance; What is the reconnaissance that gains information about targeted computers and networks without direct interaction with the systems? i.e google search, Public records, new releases, social media etc.",
      answers: {
          a: 'Passive Recon',
          b: 'Active Recon'
      },
      correctAnswer: 'a'
  },
  {
      question: "In what class is the first three bits always 110 and the first 21 bits are the network address?",
      answers: {
          a: 'Class A',
          b: 'Class B',
          c: 'Class C',
          d: 'Class D',
          e: 'Class E',
      },
      correctAnswer: 'c'
  },
  {
      question: "UNION, TIME and ERROR are techniques for what attacks?",
      answers: {
          a: 'SQL Injection',
          b: 'Directory Traversal',
          c: 'XSS'
      },
      correctAnswer: 'a'
  },
  {
      question: "Of the two internal commands for the SMTP service, what on reveals the actual address of user's aliases and lists of e-mail(mailing lists).",
      answers: {
          a: 'VRFY',
          b: 'HELO',
          c: 'EXPN',
          d: 'DELE',
          e: 'EHLO',
      },
      correctAnswer: 'c'
  },
  {
      question: "Informational Responses",
      answers: {
          a: '100-199',
          b: '200-299',
          c: '300-399',
          d: '400-499'
      },
      correctAnswer: 'a'
  },
  {
      question: " True or False: PGP and AES are strong encryption algorithms",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'True'
  },
  {
      question: "What does Microsoft defender antivirus do?",
      answers: {
          a: 'Protects against phishing or malware websites and applications, and the downloading of potential malicious files. Checks for unrecognised apps and files from the web',
          b: 'Check files, folders, running program on your hard disk, etc for viruses and threats'
      },
      correctAnswer: 'b'
  },
  {
      question: "What am I? I inform web crawlers where to index and not index. Tells the search engines which pages to access and index on your website and which pages not to. I am a file that tells search engine spiders to not crawl certain pages or sections of a website",
      answers: {
          a: 'Robots.txt',
          b: 'Rainbow Table',
          c: '/var/www/html',
          d: 'System32'
      },
      correctAnswer: 'a'
  },
  {
      question: "True of False: together SMTP and POP/IMAP allows the user to send outgoing mail and retrieve incoming mail. ",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: "What am I? Modules available to run after an initial compromise has occured",
      answers: {
          a: 'Exploit',
          b: 'Auxiliary Functions',
          c: 'Post-Exploitation'
      },
      correctAnswer: 'c'
  },
  {
      question: " _________ are a way for the client to show their intended action when making an HTTP request.",
      answers: {
          a: 'HTTP HEader',
          b: 'HTTP Method',
          c: 'HTTP Request',
          d: 'HTTP response'
      },
      correctAnswer: 'b'
  },
  {
      question: "telnet webserveraddress 80 HEAD/HTTP/1.0 can be used to _____ a webserver",
      answers: {
          a: 'Fingerprint',
          b: 'Exploit',
          c: 'Crash',
      },
      correctAnswer: 'a'
  },
  {
      question: "What port uses TFTP",
      answers: {
          a: '139',
          b: '69',
          c: '445',
          d: '22',
          e: '111',
          f: '21'
      },
      correctAnswer: '69'
  },
  {
      question: "True or False: Bitlocker does not work best with TPM as the 2 clash",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'b'
  },
  {
      question: "What method would be used to remove a picture you've uploaded to your account?",
      answers: {
          a: 'PUT',
          b: 'DELETE',
          c: 'REMOVE',
          d: 'GET'
      },
      correctAnswer: 'b'
  },
  {
      question: "What is rockyou.txt used for?",
      answers: {
          a: 'used to identify Web Crawlers (Index and not index)',
          b: 'a Famous wordlist'
      },
      correctAnswer: 'b'
  },
  {
      question: "True or False: when using a salt value in a password encryption algorithm, two users with the same password could have different password hashes",
      answers: {
          a: 'True',
          b: 'False',
      },
      correctAnswer: 'a'
  },
  {
      question: "True or False: Exploiting secretsdump.py effectively gives you full control over the Active Directory",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: "2x same keys are a part of what cryptography?",
      answers: {
          a: 'Asymmetric',
          b: 'Symmetric',
          c: 'Hashing'
      },
      correctAnswer: 'Hashing'
  },
  {
      question: "Are LM and NTLM salted passwords?",
      answers: {
          a: 'Yes',
          b: 'No',
          c: 'No they are peppered'
      },
      correctAnswer: 'b'
  },
  {
      question: "http://user:password@tryhackme.com:80/view-room?id=1#[task3]\nThis is an example of a URL, what is the component highlighted in [] called?",
      answers: {
          a: 'Scheme',
          b: 'User',
          c: 'Host/Domain',
          d: 'Port',
          e: 'Path',
          f: 'Query String',
          g: 'Fragment'
      },
      correctAnswer: 'g'
  },
  {
      question: "What are the example(s) of a TLS/SSL vulnerability?",
      answers: {
          a: 'POODLE',
          b: 'HEARTBLEED',
          c: 'BEAST',
          d: 'CRIME',
          e: 'All of the Above'
      },
      correctAnswer: 'e'
  },
  {
      question: " Examples of typical Input/Output devices?",
      answers: {
          a: 'Desktop, documents, files and machines',
          b: 'printers, hard disks, keyboards and mouses'
      },
      correctAnswer: 'b'
  },
  {
      question: "How many bits in an IPv4 address?",
      answers: {
          a: '16 bits',
          b: '32 bits',
          c: '64 bits',
          d: '128 bits'
      },
      correctAnswer: 'b'
  },
  {
      question: "Session hijacking is performed after...",
      answers: {
          a: 'The 3 way handshake',
          b: 'connection',
          c: 'nmap scan'
      },
      correctAnswer: 'a'
  },
  {
      question: "What is the acronym for IKE?",
      answers: {
          a: 'IKE Turner',
          b: 'Internet Key Exhange',
          c: 'IP Key Exchange'
      },
      correctAnswer: 'b'
  },
  {
      question: "Request or Response headers? 'headers that are sent from the client (usually your browser) to the server'",
      answers: {
          a: 'Request Headers',
          b: 'Response Headers'
      },
      correctAnswer: 'a'
  },
  {
      question: " What am I? a method of sending data over the internet where the data is encrypted and the orginal IP address information is also encrypted",
      answers: {
          a: 'Secure Shell',
          b: 'Tunnel Mode'
      },
      correctAnswer: 'b'
  },
  {
      question: "Usernames, name, ID number, employee number, SSN come under what?",
      answers: {
          a: 'Accounting',
          b: 'Authorisation',
          c: 'Identification',
          d: 'Authentication'
      },
      correctAnswer: 'c'
  },
  {
      question: "What am I? a unique address that identifies a device on the internet or a local network?",
      answers: {
          a: 'IPsec',
          b: 'Internet Protocol',
          c: 'IP Address'
      },
      correctAnswer: 'c'
  },
  {
      question: "What is the Kerberos RID in Windows?",
      answers: {
          a: '0',
          b: '50',
          c: '500',
          d: '501',
          e: '502'
      },
      correctAnswer: 'e'
  },
  {
      question: "What is the command for doing a trace route in Windows?",
      answers: {
          a: 'Traceroute',
          b: 'tracert',
          c: '-tr ac 3'
      },
      correctAnswer: 'b'
  },
  {
      question: "If we find an SMB server that does not require a username and password or find valid credentials, what can happen?",
      answers: {
          a: 'Attacker will still not be able to retrieve anything as the SMB protocol holds no weight',
          b: 'Attacker can only access the shares as the other objects are still secured',
          c: 'We can get a list of shares, usernames, groups, permissions, policies, services, etc'
      },
      correctAnswer: 'c'
  },
  {
      question: "What algorithm could be used to negotiate a shared encryption key?",
      answers: {
          a: 'SHA-256',
          b: 'YAK',
          c: 'Blowfish',
          d: 'Diffie-Hellman algorithm',
          e: 'MD5'
      },
      correctAnswer: 'd'
  },
  {
      question: "What header tells the web server what browser is being used?",
      answers: {
          a: 'Host',
          b: 'User-Agent',
          c: 'Cookies',
          d: 'Content-Length'
      },
      correctAnswer: 'b'
  },
  {
      question: "If a system on Class B subnet has the IP address 172.16.58.195 and the subnetmask is 255.255.0.0 what will the broadcast address be?",
      answers: {
          a: '172.16.0.0',
          b: '172.16.255.255',
          c: '255.255.58.195'
      },
      correctAnswer: 'b'
  },
  {
      question: "How would you connect to a Telnet server with IP 10.10.10.3 on port 23?",
      answers: {
          a: 'telnet 10.10.10.3 -p0-',
          b: 'nmap 10.10.10.3 -p23',
          c: '10.10.10.3 telnet 23',
          d: 'telnet 10.10.10.3 23'
      },
      correctAnswer: 'd'
  },
  {
      question: "What are the protection areas in windows security?",
      answers: {
          a: 'Firewall & Network Protection',
          b: 'App & Browser Control',
          c: 'Device Security',
          d: 'Virus & threat Protection',
          e: 'All of the above'
      },
      correctAnswer: 'e'
  },
  {
      question: "What encryption algorithm uses prime numbers to generate keys?",
      answers: {
          a: 'RC4',
          b: 'RSA',
          c: 'MD5'
      },
      correctAnswer: 'b'
  },
  {
      question: "What is a set of requirements, process, principles, and models that determines the structure and behaviour of an organisation's information systems?",
      answers: {
          a: 'EISA',
          b: 'ISO',
          c: 'NIST',
          d: 'MITRE'
      },
      correctAnswer: 'a'
  },
  {
      question: "According to Identity and Access Management, proving you are the legitimate user should always be done with ___________.",
      answers: {
          a: 'Multifactor authentication (use of 2 examples i.e something you know and something you have)',
          b: 'Strong Password',
          c: 'Strong Encrypion Algortithms'
      },
      correctAnswer: 'a'
  },
  {
      question: "What are Cookies mostly used for?",
      answers: {
          a: 'Website Authentication',
          b: 'Security'
      },
      correctAnswer: 'a'
  },
  {
      question: "What am I? my purpose is to simultaneously verify both data integrity (via cryptographic hashing function) and message authenticity (use of secret key)",
      answers: {
          a: 'Tunnel Mode',
          b: 'Strict Transport Security',
          c: 'HMAC'
      },
      correctAnswer: 'c'
  },
  {
      question: "What is the administrators RID in Windows?",
      answers: {
          a: '250',
          b: '500',
          c: '5000',
          d: '502',
          e: '501'
      },
      correctAnswer: 'b'
  },
  {
      question: "True or False: CIDR (Classless Inter-Domain Routing) is based on a variable legnth subnet masks that allows for much more efficient use of IP addresses.",
      answers: {
          a: 'True',
          b: 'False'
      },
      correctAnswer: 'a'
  },
  {
      question: "What layer comprises of Frames, Ethernet, PPP, Switch and Bridge?",
      answers: {
          a: 'Application',
          b: 'Presentation',
          c: 'Session',
          d: 'Transport',
          e: 'Network',
          f: 'Data Link',
          g: 'Physical'
      },
      correctAnswer: 'f'
  },
  {
      question: "Deters the actor from attempting the threat i.e warning sign",
      answers: {
          a: 'Compensating Control',
          b: 'Preventitive Control',
          c: 'Recovery',
          d: 'Detective Control',
          e: 'Deterrent Control'
      },
      correctAnswer: 'e'
  },
  {
      question: "Which is Class B",
      answers: {
          a: '/8',
          b: '/16',
          c: '/24',
          d: '/4'
      },
      correctAnswer: 'b'
  },
  {
      question: "Which is Class A",
      answers: {
          a: '/8',
          b: '/16',
          c: '/24'
      },
      correctAnswer: 'a'
  },
  {
      question: "What forces the terminiation of a connection (in both directions)?",
      answers: {
          a: 'SYN',
          b: 'ACK',
          c: 'RST',
          d: 'FIN'
      },
      correctAnswer: '.c'
  },
  {
      question: " How can a file be recovered if a user encrypted a project file with his public key; later, an administrator accidentally deleted his account that had exclusive access to his private key?",
      answers: {
          a: 'His file cannot be recovered',
          b: 'If the organisation uses a recovery agent',
          c: 'If the organisation has a continuity plan'
      },
      correctAnswer: 'b'
  },
  {
      question: "What is the format for cached domain credentials?",
      answers: {
          a: 'MISSIS-CACHE',
          b: 'MRS-CACHE',
          c: 'MR-CACHE',
          d: 'MS-CACHE'
      },
      correctAnswer: 'd'
  },
  {
      question: "What one is Class C?",
      answers: {
          a: '/8',
          b: '/16',
          c: '/24',
          d: '/32'
      },
      correctAnswer: 'c'
  },
  {
      question: "___ more simplistic in its approach of downloading the inbox from the mail server, to the client.",
      answers: {
          a: 'IMAP',
          b: 'SMTP',
          c: 'POP'
      },
      correctAnswer: 'c'
  },
  {
      question: "What layer of the OSI model is responsible for creating the data for the packets. Acts as the interface between the user and the network?",
      answers: {
          a: 'Application',
          b: 'Presentation',
          c: 'Session',
          d: 'Transport',
          e: 'Network',
          f: 'Data Link',
          g: 'Physical'
      },
      correctAnswer: 'f'
  },
  {
      question: "What is the acronym for CSRF",
      answers: {
          a: 'Cross Site Request Forgery',
          b: 'Cross Site Response Forgery'
      },
      correctAnswer: 'a'
  },
  {
      question: "What request am I? used for submitting data to a web server to update information",
      answers: {
          a: 'DELETE',
          b: 'GET',
          c: 'PUT',
          d: 'POST',
      },
      correctAnswer: 'c'
  },
  {
      question: "Ports 1024-49,151 are",
      answers: {
          a: 'Well-Known Ports',
          b: 'Registered Ports',
          c: 'Dynamic'
      },
      correctAnswer: 'b'
  },
  {
      question: "When does ASREPRoasting occur?",
      answers: {
          a: 'When a user account has the privilege "does not require Pre-Authentication" set',
          b: 'When a user account has the privilege "Requires Pre-Authentication" set',
          c: 'When an account has lockout policies',
          d: 'When a user account is not encrypted'
      },
      correctAnswer: 'a'
  },
  {
      question: "What protocol can the tool Onesixtyone be used for?",
      answers: {
          a: 'FTP',
          b: 'SMTP',
          c: 'POP3',
          d: 'SNMP'
      },
      correctAnswer: 'd'
  },
  {
      question: "Nmap, hping3, Angry IP scanner, solar-winds engineer toolkit, advanced IP scanner and Pinkie are _____ tools",
      answers: {
          a: 'Exploitation Tools',
          b: 'Ping Scanning Tools',
          c: 'Enumeration Tools'
      },
      correctAnswer: 'b'
  },
  {
      question: "What tool is this: bruteforce discovery of users, passwords and password spray",
      answers: {
          a: 'Burp Suite',
          b: 'Kerbrute',
          c: 'Nessus',
          d: 'Nikto'
      },
      correctAnswer: 'b'
  },
  {
      question: "What methodology involes host identification, scan for oepn ports and identifies network details?",
      answers: {
          a: 'Information Gathering',
          b: 'Enumeration',
          c: 'Exploitation',
          d: 'Post Exploitation',
          e: 'Reporting'
      },
      correctAnswer: 'a'
  },
  {
      question: "If the following Windows command is run: net user Tia.fidus pa55word123, what will happen?",
      answers: {
          a: 'Account is Permanently locked out',
          b: 'Password is reset to pa55word123'
      },
      correctAnswer: 'b'
  },
  {
      question: "What ports are 49,152-65,535",
      answers: {
          a: 'Well Known ports',
          b: 'Registered Ports',
          c: 'Dynamic Ports'
      },
      correctAnswer: 'c'
  },
  {
      question: "What type of cryptography is faster?",
      answers: {
          a: 'Asymmetric',
          b: 'Symmetric'
      },
      correctAnswer: 'b'
  },
  {
      question: "Explain the following command: ping -r 5 fidusinfosec.co.uk -n2",
      answers: {
          a: 'Pings fidusinfosec.co.uk with 4 echo requests whilde recording 5 count hops',
          b: 'Pings fidusinfosec.co.uk with 2 echo requests while recording 5 count hops'
      },
      correctAnswer: 'b'
  },
  {
      question: "Hacker that is hired by a government or entity related",
      answers: {
          a: 'Hacktivist',
          b: 'White Hat',
          c: 'Black Hat',
          d: 'Suicide Hackers',
          e: 'State-Spondored Hacker',
          f: 'Gray Hat',
          g: 'CyberTerrorist',
          h: 'Script Kiddie/Skiddies'
      },
      correctAnswer: 'e'
  },
];
//var maxQuestions = 10;
var maxQuestions = prompt("Please enter the number of questions you'd like to answer", 100)
maxQuestions = (maxQuestions) ? maxQuestions : questions.length;
var quizContainer = document.getElementById('quiz');
var resultsContainer = document.getElementById('results');
var scoreContainer = document.getElementById('score');
var submitButton = document.getElementById('submit');  

function generateQuiz(questions, quizContainer, resultsContainer, submitButton, maxQuestions, scoreContainer) {
    var shuffledQuestions = questions.sort(function() {
      return 0.5 - Math.random();
    });
    var selectedQuestions = shuffledQuestions.slice(0, maxQuestions);
    // var numberQuestions = maxQuestions || questions.length;
  
    // add total number of questions element
    var totalQuestionsElement = document.createElement('div');
    totalQuestionsElement.innerHTML = 'Total number of questions: ' + maxQuestions;
    quizContainer.appendChild(totalQuestionsElement);
  
    // show questions right away
    showQuestions(selectedQuestions, quizContainer, maxQuestions);
  
    // on submit, show results
    submitButton.onclick = function() {
      showResults(questions, quizContainer, resultsContainer, scoreContainer);
    };
  }

function showQuestions(questions, container, maxQuestions) {
  // we'll need a place to store the output and the answer choices
  var output = [];
  var answers;
//   var numberQuestions = maxQuestions || questions.length

  // for each question...
  for(var i=0; i < maxQuestions; i++){
    
    // first reset the list of answers
    answers = [];

    // for each available answer...
    for(letter in questions[i].answers){

      // ...add an html radio button
      answers.push(
        '<label>'
          + '<input type="radio" name="question'+i+'" value="'+letter+'">'
          + letter + ': '
          + questions[i].answers[letter]
        + '</label>'
      );
    }

    // add this question and its answers to the output
    output.push(
      '<div class="question">' + (i + 1) + '. ' + questions[i].question + '</div>'
      + '<div class="answers">' + answers.join('') + '</div>'
    );
  }

  // finally combine our output list into one string of html and put it on the page
  container.innerHTML = output.join('');
}

function showResults(questions, quizContainer, resultsContainer, scoreContainer) {
    // gather answer containers from our quiz
    var answerContainers = quizContainer.querySelectorAll('.answers');
    
    // keep track of user's answers
    var userAnswer;
    var numCorrect = 0;

    // for each question...
    for(var i=0; i< maxQuestions; i++) {
      // find selected answer
      userAnswer = (answerContainers[i].querySelector('input[name=question'+i+']:checked')||{}).value;

      // find correct answer
      correctAnswer = questions[i].correctAnswer;
      
      // if answer is correct
      if(userAnswer===questions[i].correctAnswer){
        // add to the number of correct answers
        numCorrect++;
        
        // color the answers green
        answerContainers[i].style.color = 'lightgreen';
      }
      // if answer is wrong or blank
      else{
        // color the answers red
        answerContainers[i].style.color = 'red';
      }
      answerContainers[i].querySelector('label[for=question'+i+'_'+correctAnswer+']').style.color = 'lightgreen';
    }

    // show number of correct answers out of total
    resultsContainer.innerHTML = numCorrect + ' out of ' + maxQuestions;
 
    scoreContainer.innerHTML = 'Score: ' + numCorrect + '/' + maxQuestions;
}
  

generateQuiz(questions, quizContainer, resultsContainer, submitButton, maxQuestions, scoreContainer);



