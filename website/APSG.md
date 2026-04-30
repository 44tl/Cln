# APSG A Practical Security Guide

A fast, practical security guide for preventing account compromise, avoiding scams, and recovering from hacked devices.

---

## Short Version

If you have no time, do these first. They block the most common real world attacks.

1. Use a password manager and make every important password unique.
2. Turn on multifactor authentication, preferably passkeys or a hardware security key for email, banking, cloud storage, and social accounts.
3. Update your phone, computer, browser, router, and apps automatically.
4. Do not click urgent links in texts, emails, ads, pop-ups, or direct messages. Open the official app or type the site address yourself.
5. Back up important files using at least one cloud backup and one offline or external backup.
6. If a device may be hacked, disconnect it from the internet and change passwords from a different clean device.
7. Never share one time codes, remote access, bank details, crypto wallet phrases, or gift card numbers with someone who contacted you.

---

## 1. Prevention

Keep software updated, use unique passwords, add phishing resistant MFA where possible, back up data, and slow down when a message pressures you to act.

### 1.1 Passwords and Passkeys

Use a password manager for every account that matters. Strong passwords should be long, random, and unique. For most people, a password manager is safer than trying to memorize variations of the same password.

Where supported, use passkeys. Passkeys are built on public key cryptography and are designed to resist phishing because they are tied to the real website or app. They are especially useful for email, Apple ID, Google, Microsoft, password managers, banking, and developer accounts.

Do not rotate passwords on a calendar unless an account, device, or service was actually compromised. Modern guidance favors long unique passwords, breach checks, and immediate changes after evidence of compromise.

### 1.2 Multifactor Authentication

Multifactor authentication stops many account takeovers even when a password is stolen. Prefer these methods in order:

1. Passkeys or FIDO2 hardware security keys.
2. Authenticator app codes or push approval with number matching.
3. SMS codes only when no stronger option exists.

**Important:** One time codes are useful, but they are not phishing resistant. If a caller, chat agent, or website asks you to read a code back, treat it as an attack.

### 1.3 Updates and App Hygiene

Turn on automatic updates for operating systems, browsers, browser extensions, messaging apps, document readers, password managers, and security tools. Attackers often move quickly after a vulnerability becomes public.

Remove apps, extensions, remote access tools, and smart devices you no longer use. Every installed component is an additional place where a bug, malicious update, weak password, or abandoned account can become a problem.

### 1.4 Backups

Use a simple backup rule: keep at least three copies of important data, on two different types of storage, with one copy offline or otherwise protected from ransomware. Test restores before you need them.

- Cloud backup protects against device loss and local hardware failure.
- External drives protect against account lockout and some cloud mistakes.
- Versioned backups help recover from accidental deletion and ransomware encryption.

### 1.5 Network and Router Security

Change the default router administrator password, keep router firmware updated, and use WPA3 or WPA2 AES encryption. Create a guest network for visitors and smart home devices so they are separated from laptops and phones that hold sensitive data.

A VPN can help on untrusted networks, but it does not make phishing, malware, or fake websites safe. HTTPS, updates, and careful login habits still matter.

### 1.6 Everyday Verification Habits

**Fast checks before you act**

- Look at the real sender address, not only the display name.
- Do not trust caller ID; it can be spoofed.
- Open official apps directly instead of using message links.
- Pause when a message creates urgency, secrecy, fear, or shame.
- Verify payment changes through a known phone number.
- Ask a trusted person before moving large sums of money.

---

## 2. If You Are Hacked

Disconnect the device, use a clean device for account recovery, protect email and financial accounts first, then scan, reset, or reinstall.

### 2.1 First Ten Minutes

1. Disconnect the suspected device from Wi-Fi, mobile data, Ethernet, and Bluetooth.
2. Do not type new passwords on that device.
3. Use a separate trusted phone or computer to check email, banking, cloud, and password manager accounts.
4. Change the password for your main email account first, then your password manager, banking, cloud storage, and social accounts.
5. Sign out of all sessions where the service allows it.
6. Revoke unknown devices, app passwords, OAuth apps, browser sync sessions, and forwarding rules.

### 2.2 Signs Worth Taking Seriously

- New account recovery email, phone number, passkey, security key, or authenticator you did not add.
- Email forwarding rules or filters you did not create.
- Unknown browser extensions, mobile configuration profiles, enterprise management profiles, or remote access software.
- Unexpected password reset emails, payment alerts, crypto withdrawals, or messages sent from your account.
- Device administrator accounts, scheduled tasks, login items, or startup apps you do not recognize.

### 2.3 Clean the Device

For low risk adware or a suspicious extension, removing the extension, uninstalling the app, updating, and scanning may be enough. For confirmed compromise, remote access scam activity, stolen financial data, or unknown administrator access, reset the device or reinstall the operating system.

| Device | What to do |
|---|---|
| iPhone or iPad | Update iOS or iPadOS, remove unknown configuration profiles and VPNs, check Apple ID devices, then erase all content and settings if compromise persists. |
| Android | Update Android and apps, remove unknown apps, check device admin apps and accessibility permissions, run Play Protect or a reputable scanner, then factory reset if needed. |
| Windows | Run Windows Security, remove unknown remote access tools and startup items, check browser extensions, then use Reset this PC or reinstall from trusted media for serious compromise. |
| macOS | Update macOS, remove unknown profiles, login items, extensions, and remote management tools, run a reputable scanner if needed, then erase and reinstall for serious compromise. |

**Do not preserve malware.** Before a reset, save only irreplaceable personal files such as documents and photos. Avoid restoring unknown apps, browser extensions, system settings, or full device images from the compromised period.

### 2.4 Safe Malware Scanner Apps

Only download scanners from the official vendor website or the official app store listing. Avoid "PC cleaner," "driver updater," "system optimizer," fake antivirus pop-ups, cracked security tools, and random download mirrors.

| Tool | Best use | Notes |
|---|---|---|
| Malwarebytes | Community trusted second opinion scans and cleanup on Windows, Mac, and Android. | The free version is useful for manual cleanup. Premium features vary by platform and plan. |
| HitmanPro | Lightweight Windows second opinion malware scanning. | Useful when you want another scanner alongside your main antivirus. Download only from HitmanPro or Sophos-linked official pages. |
| ESET Online Scanner | Free one time Windows malware scan. | Useful for a deeper second opinion check when you do not want to replace your main antivirus. |
| Bitdefender Virus Scanner for Mac | Mac malware and file scanning. | Install through the official Mac App Store path from Bitdefender's page. |

**Phone note:** Android supports malware scanning apps. iOS does not allow normal antivirus apps to scan the whole device, so iPhone security apps mainly provide web, text, call, privacy, and scam protection.

Do not run several real time antivirus products at the same time. It can slow the computer down and cause conflicts. Use one main real time protection tool, then use trusted second opinion scanners manually when needed.

### 2.5 Money, Identity, and Reporting

If money or identity data is involved, contact your bank or card issuer immediately. Ask about reversing charges, replacing cards, blocking transfers, and adding extra verification. In the United States, report fraud to the FTC and internet crime to the FBI IC3. Consider a credit freeze with Equifax, Experian, and TransUnion if Social Security or identity data was exposed.

Document dates, messages, phone numbers, wallet addresses, transaction IDs, screenshots, remote access tools installed, and accounts touched. This helps banks, platforms, and law enforcement act faster.

---

## 3. Current Scams

The common pattern is pressure plus impersonation: a fake company, bank, government office, employer, friend, romantic partner, or investment expert pushes you to send money, codes, access, or data.

### 3.1 Tech Support Scams

Fake pop-ups, search ads, calls, and emails may claim your computer is infected or your subscription renewed. The scammer tries to get remote access, payment, or banking information. Real security warnings do not tell you to call a phone number in a pop-up.

If it happens, close the browser, disconnect if necessary, run a security scan, uninstall remote access tools, change passwords from a clean device, and call your bank if you paid.

### 3.2 AI Voice, Video, and Message Fraud

AI tools make impersonation cheaper. A scam may use a cloned voice, realistic video, polished writing, or personal details from social media. Treat unexpected urgent requests as unverified even when the voice or video looks familiar.

Use a family code word for emergencies. Verify through a separate known channel, such as calling the person back on a saved number.

### 3.3 Bank, Delivery, Tax, and Government Impersonation

Scammers pose as banks, delivery companies, tax agencies, police, customs, or regulators. They may claim your money is unsafe, your package is blocked, or you are under investigation. Government agencies and banks do not require secrecy, gift cards, crypto, gold, courier pickup, or payment to avoid arrest.

### 3.4 Investment, Crypto, and Romance Scams

In relationship-based investment scams, the attacker builds trust over days or months, then introduces a fake trading platform. The website may show fake profits and allow small withdrawals before blocking larger withdrawals with invented fees or taxes.

- Do not invest based on a person you met through messaging, social media, or a dating app.
- Check brokers and platforms through official financial regulators.
- Do not send more money to recover money already lost.
- Recovery companies that promise to retrieve crypto are often another scam.

### 3.5 Business Email Compromise

Attackers compromise or impersonate email accounts to redirect invoices, payroll, wire transfers, or vendor payments. Any request to change payment details should be verified through a known phone number or previously established channel.

### 3.6 QR Codes, Ads, and Fake Apps

Malicious QR codes and ads can lead to fake login pages or app downloads. Avoid scanning payment or login QR codes from stickers, posters, unexpected emails, or public places unless you can verify the source. Install apps from official stores and check the developer name.

### 3.7 Malware and Zero-Click Exploits

Most malware still needs a click, install, stolen password, or social engineering. Advanced zero-click attacks exist, especially against high risk targets, but the best everyday defense is prompt updates, device restart after updates, reduced app exposure, and strong account protection.

---

## 4. Device Notes

Phones, computers, routers, and smart devices need updates, screen locks, account protection, and fewer unnecessary apps.

### 4.1 Phones

- Use a six digit or longer passcode, not a simple pattern.
- Enable lost device tracking and remote wipe.
- Review app permissions for location, microphone, camera, contacts, photos, SMS, accessibility, and notifications.
- Disable lock screen previews for sensitive messages.
- Ask your mobile carrier for a port out PIN or SIM swap protection.

### 4.2 Computers

- Use a standard user account for daily work where practical.
- Keep full disk encryption enabled: BitLocker on Windows, FileVault on macOS.
- Remove browser extensions you do not need.
- Do not install remote access tools unless you know why they are needed.
- Lock the screen automatically after inactivity.

### 4.3 Smart Home and IoT

- Change default passwords and disable unused cloud features.
- Keep cameras, TVs, speakers, and appliances on a guest or IoT network.
- Replace devices that no longer receive security updates.
- Do not expose router, camera, NAS, or remote desktop admin panels directly to the internet.

---

## 5. Myths

| Myth | Reality |
|---|---|
| Macs and iPhones cannot be hacked. | They are generally well protected, but phishing, stolen passwords, malicious profiles, spyware, and browser bugs still affect Apple users. |
| Incognito mode makes you anonymous. | It mostly prevents local history from being saved. It does not stop phishing, malware, account tracking, employer monitoring, or ISP visibility. |
| Antivirus fixes every compromise. | Security tools help, but serious compromise may require account recovery, credential changes, factory reset, or OS reinstall. |
| SMS MFA is useless. | SMS is weaker than passkeys or authenticator apps, but it is usually better than password only login when no stronger option exists. |
| A VPN makes unsafe sites safe. | A VPN changes network routing. It does not verify people, block all malware, or make fake login pages legitimate. |
| Paying ransom guarantees recovery. | Payment can fail, fund criminals, and mark you as a profitable target. Backups and reporting are safer recovery paths. |

---
