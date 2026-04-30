# Instaler.exe Fake Game Dropper and Multi Stealer Analysis

> **Defensive report.** This analysis is written for defenders, incident responders, and anyone who wants to understand what this specific piece of malware actually does under the hood  and how to clean it up.

---

## At a Glance

| Field | Value |
|---|---|
| **SHA-256** | `7123e1514b939b165985560057fe3c761440a9fff9783a3b84e861fd2888d4ab` |
| **File name** | `Instaler.exe` (note the deliberate typo) |
| **File size** | 62.1 MB |
| **Type** | PE32 Windows Executable  Dropper / Infostealer |
| **First seen** | May 2025 |
| **Detection names** | `Trojan:W32/AntiAV` (F-Secure), `Trojan.Win32.ANTIAV.AB` (Trend Micro), `Trojan.AntiAV.Win32.12104` (Zillya) |
| **Signer** | Qihoo 360 Software (Beijing) Co. Ltd  likely spoofed/abused |
| **Companion files** | `Instaler.py`, 4 data folders |
| **Threat class** | Token Logger + Browser Infostealer + Dropper |

---

## How the Victim Got Here (Common way)

The infection started with a pirated game download. The archive was named something generic  *"Free Download Files"*  and had no actual game name attached. That's a red flag most people learn to recognize, but only in hindsight.

Unzipping the archive revealed a familiar-looking structure: an `Instaler.exe`, an `Instaler.py`, and four folders of what looked like game assets. The total size was 62 MB. The real game it was impersonating sits closer to 1 GB. That gap  and the typo in "Instaler"  were the tells.

The victim ran the `.exe`. Nothing visible happened. No install wizard, no progress bar, no game. Just silence. They clicked a few more times, assumed it was broken, deleted the folder, and moved on.

By the time they closed the laptop that evening, it was already over. Credentials had been scooped up and the malware had phoned home.

---

## The Dropper Layer: What the .exe Actually Does

The `Instaler.exe` is not really an installer at all  it's a **dropper**. Its job is to land on the machine, deploy the real payload, set up persistence, and disappear quietly. The 62 MB bulk comes from bundled Python runtime assets and game-engine files used as camouflage. This is a known technique tied to the **RenEngine loader family**, which uses the Ren'Py visual novel engine as cover.

When the user runs the executable, a few things happen in rapid succession:

### Stage 1  Fake Loading Screen
The exe briefly shows something that looks like a loading screen (or nothing at all, in some variants). This buys a few seconds for the actual work to start in the background. The user thinks the "game" is launching.

### Stage 2  Python Payload Execution
The companion `Instaler.py`  or an obfuscated Python script embedded inside the exe  is executed. Python is a convenient choice for attackers: it's cross platform, the standard library is rich, and compiled `.pyc` files are harder to read at a glance than raw source. The script is responsible for the actual stealing logic.

### Stage 3  Sandbox / Environment Check
Before doing anything suspicious, the malware checks its environment. It looks for:

- Virtual machine artifacts (VMware registry keys, VirtualBox guest additions, Hyper-V indicators)
- Debugger presence (`IsDebuggerPresent` API calls)
- Low screen resolution (a common VM signature)
- Process names associated with analysis tools (Wireshark, Process Monitor, x64dbg, etc.)

If any of these are detected, the malware may simply exit without leaving a trace. This is part of what makes it hard to catch in automated sandboxes  and it's also why some AV engines didn't flag it at first.

### Stage 4  Persistence via Task Scheduler
After the initial run, the malware installs itself for persistence. The victim found a suspicious entry in Task Scheduler called `USER_ESRV_SVC_QUEENCREEK`. This is a known technique: disguising a malicious scheduled task with a name that resembles a legitimate Windows service. The task ensures the stealer component re-runs on login, even after the original files are deleted.

A second persistence mechanism drops `XPFIX.exe` into `AppData\Roaming\AgentX\`. This file is the resident component  detected separately by VirusTotal as **AntiAV**. Its job is to sit quietly on the machine and resist removal.

---

## The Stealing Layer: What Gets Taken

Once the dropper has done its setup work, the infostealer payload runs immediately. Here's what it goes after, in roughly the order it operates:

### Browser Session Tokens & Cookies
Every major browser stores session cookies in a SQLite database on disk. Chrome, Edge, Brave, Opera, Firefox the paths are well documented and the malware knows all of them. Session cookies let you stay logged into a website without re-entering your password, which means anyone who has your session cookie can impersonate you in a browser right now, no password required.

The malware copies these databases, decrypts the cookies using the browser's own encryption key (which is also stored locally under `AppData`), and sends the raw token values to a remote server.

**Affected browsers include:**
- Google Chrome (`\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies`)
- Microsoft Edge (`\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies`)
- Brave, Opera, Vivaldi, and other Chromium-based browsers

### Saved Passwords from Chrome / Google Password Manager
Chrome encrypts saved passwords using the Windows Data Protection API (DPAPI)  but only the key is protected, not the decryption process. The malware, running under the same user account, can call the same DPAPI functions Chrome does and decrypt every saved password in the profile. The output is a plaintext list: URL, username, password.

If you had "Save password?" enabled in Chrome and clicked yes at any point, those credentials are now compromised.

### Discord Auth Tokens
Discord stores authentication tokens in plain text inside `AppData\Roaming\discord\Local Storage\leveldb\`. No encryption, no hashing  just text files. The malware grabs every token file from every Discord installation it can find, sends them out, and the attacker can immediately log into the victim's account from any device in the world.

In the victim's case, two Discord accounts were drained and immediately used to send scam links to contacts. This is typical behavior  the attacker runs an automated script that logs in, mass-messages everyone in the friend list, then moves on.

### Roblox Session Tokens
The malware specifically looked for Roblox account data. A folder was created under the Ren'Py data directory with a Roblox game ID as the folder name, and inside: `tokens.txt` and `security-key.txt`. These are harvested Roblox authentication tokens.

The victim noticed this when their main Roblox account showed another device playing a game they'd never heard of. The attacker had successfully hijacked the session.

---

## The AntiAV Component: XPFIX.exe

`XPFIX.exe`, dropped into `AppData\Roaming\AgentX\`, is the part of this infection that gives the whole package its "AntiAV" classification. This component's purpose is **anti detection and persistence maintenance**. It does a few things:

- **Monitors AV activity**  watches for processes associated with antivirus tools and can interfere with their execution or hide from their scans
- **Maintains the scheduled task**  if the `USER_ESRV_SVC_QUEENCREEK` task is deleted, this component can re-create it
- **Disables Windows Defender features**  modifies registry keys or Group Policy entries to weaken real-time protection
- **Cleans up evidence**  deletes logs and temporary files that might reveal what happened

This is why ESET's scan came back clean even after the machine was clearly compromised. The AntiAV component was actively working against detection.

---

## The Loot Folder

One of the clearest signs of infection the victim found was the loot folder under `AppData\Roaming\RenPy\[ROBLOX-GAME-ID]\tokens\`. This is where the malware staged its collected data before exfiltrating it:

```
AppData\
  Roaming\
    RenPy\
      [game-id]\
        tokens\
          tokens.txt       ← Discord + Roblox auth tokens
          security-key.txt ← Browser encryption key(s)
```

The attacker's command-and-control (C2) server would periodically collect these files, after which the local copies might be deleted to hide the trail. Finding this folder intact meant the exfiltration was still ongoing or had only recently completed.

---

## The Infection Chain, Summarized

```
Fake game archive (ZIP)
  └─ Instaler.exe  ← user runs this
       ├─ Launches Instaler.py (stealer logic)
       │    ├─ Grabs browser cookies + passwords
       │    ├─ Grabs Discord tokens
       │    ├─ Grabs Roblox tokens
       │    └─ Writes loot to RenPy staging folder
       ├─ Drops XPFIX.exe → AppData\Roaming\AgentX\
       ├─ Creates scheduled task USER_ESRV_SVC_QUEENCREEK
       └─ Exfiltrates data to C2 server
```

---

## Indicators of Compromise (IOCs)

If you think you've been hit by this or something similar, these are the things to look for:

**Files:**
- `Instaler.exe` (SHA-256: `7123e1514b939b165985560057fe3c761440a9fff9783a3b84e861fd2888d4ab`)
- `Instaler.py` in the same directory
- `XPFIX.exe` at `%APPDATA%\AgentX\XPFIX.exe`
- Any folder under `%APPDATA%\RenPy\` with a numeric name and a `tokens\` subdirectory

**Scheduled Tasks:**
- `USER_ESRV_SVC_QUEENCREEK` or similar fake-service-sounding names you don't recognize

**Registry:**
- Check `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` for unexpected entries
- Check `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache` for the above task

**Behavioral:**
- Discord accounts sending messages you didn't write
- Unexpected logins to Google, Roblox, or other accounts from foreign IPs
- Google account notifications about "security key deleted" or new device added

---

## What To Do If You're Infected

This is a real infostealer, not a joke. Half-measures won't cut it. Here's the correct response:

### Immediate (do this before touching any passwords)

1. **Disconnect from the internet.** Physically, if possible  unplug ethernet, turn off Wi-Fi. If the malware is still running, it may be watching what you type right now.
2. **Do not try to fix it from the infected machine.** Anything you do  including logging into accounts to change passwords  can be intercepted by a keylogger or token grabber that's still active.

### From a clean device

3. **Revoke all sessions on every service you were logged into.** Discord, Google, Roblox, Steam, GitHub, everything. Every platform has a "Log out all devices" button  use it.
4. **Change passwords** for every account that was logged into the browser on the infected machine. Assume all saved passwords are stolen.
5. **Enable 2FA (TOTP, not SMS)** on everything that matters. Authenticator apps give you session tokens that expire quickly and can't be extracted the same way browser cookies can.
6. **Generate new Discord tokens**  the only way is to change your Discord password, which invalidates all existing tokens.

### On the infected machine

7. **Run Microsoft Defender Offline scan.** This boots outside Windows before the malware can hide itself, giving the scanner a fair fight.
8. **Delete the scheduled task** `USER_ESRV_SVC_QUEENCREEK` via Task Scheduler (`taskschd.msc`).
9. **Delete** `%APPDATA%\AgentX\` and `%APPDATA%\RenPy\[any-numeric-folder]\`.
10. **Run Malwarebytes** (free version is sufficient) as a second opinion scanner.

### The honest take

If this malware ran to completion and had time to exfiltrate, a full Windows reinstall is the only way to be certain you're clean. It's inconvenient, but it's the only guarantee. At minimum, act as if every credential on that machine is burned  because it probably is.

---

## Why This Family Is Hard to Catch

Several design choices make this dropper harder to catch than average:

**Signed binary appearance.** The file carries metadata linking it to Qihoo 360, a legitimate Chinese security company. This doesn't mean 360 made the malware  signatures can be spoofed or stolen  but it raises the threshold for suspicion in automated scanners that weight code-signing as a trust signal.

**Ren'Py camouflage.** Bundling the malware inside a Ren'Py visual novel engine package is clever. Ren'Py is a real, widely-used game development tool. Its executables naturally have large file sizes, bundled Python runtimes, and unconventional directory structures  all things that make them noisy and hard to fingerprint with traditional signatures.

**Environment checks.** The sandbox detection logic means the malware may behave completely differently  or not at all  when run in an automated analysis environment, which is how most AV vendors test new samples.

**Python payload.** Python bytecode (`.pyc`) is harder to reverse than compiled C++ and can be obfuscated further with tools like PyArmor or Nuitka. Many AV engines have weaker heuristics for Python-based threats.

---

## The Bigger Picture

This specific file is part of a broader campaign. Kaspersky named the loader family **RenEngine** in early 2026 and documented its evolution: early variants dropped the Lumma stealer, later ones switched to ACR Stealer and Vidar. The delivery mechanism  fake pirated games built on the Ren'Py engine  has stayed consistent throughout, because it works. Pirated game seekers are exactly the kind of user who will click through warnings, disable AV, and run unsigned executables without thinking twice.

The takeaway isn't "don't pirate games" (though that's also true). It's that this category of threat  a convincingly sized archive, a plausible-looking folder structure, a slight typo in the executable name  is genuinely effective at bypassing human suspicion. Knowing what to look for is the first step to not running it.

---

## References

- [Microsoft Q&A thread  original victim report](https://learn.microsoft.com/en-us/answers/questions/3847179/my-laptop-got-infected-with-token-logger-infosteal)
- [Kaspersky  RenEngine Loader analysis](https://me-en.kaspersky.com/about/press-releases/kaspersky-identifies-renengine-loader-distributed-through-pirated-games-and-software)
- [Trend Micro  Trojan.Win32.ANTIAV threat encyclopedia](https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/trojan.win32.antiav.ap)
- [SOC Prime  RenEngine & HijackLoader chain breakdown](https://socprime.com/active-threats/renengine-loader-and-hijackloader-analysis/)
- [VirusTotal report](https://www.virustotal.com/gui/file/7123e1514b939b165985560057fe3c761440a9fff9783a3b84e861fd2888d4ab)

---

*Analysis written for defensive and educational purposes. All findings are based on publicly reported information and community submissions.*