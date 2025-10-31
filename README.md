# ZETCIPHER

> **Cryptography for Secure Token and Verification**

**📧 Author:** anonputraid
**Created:** 14/10/2025
**Version:** v1.0

---
![Banner Zet-cipher](src/images/zet-cipher.png "Banner Zet-cipher")

ZetCipher is an **open-source security framework** that combines multiple cryptographic techniques to create self-contained, secure, and context-bound tokens. It challenges the conventional belief that numerical cryptography is inherently weak introducing a new paradigm where **security is derived from the owner’s unique thought process**.

👉 **Try it online:** [https://zetcipher.getbitlab.com](https://zetcipher.getbitlab.com)
---

## 🧭 About ZetCipher

ZetCipher is not just a cryptographic library it’s a *philosophy of ownership-based security*. Imagine the number `100`. Without knowing how it was created, you cannot truly understand its meaning. Was it `50 + 50`, `1000 - 900`, or `10 × 10`? The possible origins are infinite.

This concept **a unique multi-step process** forms what we call a **"Secret Universe"**, the core of ZetCipher’s security. Only the original creator can trace and interpret the value within.

> Like an ancient mark on stone meaningless to others but full of intent to its creator ZetCipher encodes security and meaning known only to its owner.

---

## 🧩 Multi-Step Process (Secret Universe)

Unlike traditional deterministic hashing algorithms that always produce the same output for identical input, **ZetCipher’s output varies per instance or environment**. Even if two systems encode the same input, their tokens will differ only the origin can decode it correctly.

This breaks deterministic constraints and introduces **contextual cryptography**, where security isn’t static but evolves based on environmental and mental parameters.

> In the quantum era, deterministic hashes may become easily reversible.  
> ZetCipher proposes a future-proof idea:  
> “A truly secure system must be tied to the *mind of its creator*, not just stored data.”

---

## ⚙️ System Requirements

- **Laravel 12** is currently the only supported framework.  
  Other versions or frameworks are not yet tested or guaranteed to work properly.

---

## 🚀 Installation & Usage

### 📦 Install via Composer
```bash
composer require zetcipher/zetcipher
```

### 🔑 Initialize Setup
```bash
php artisan zetcipher:key
```

### ⚙️ Configure `.env`
```php
ZETCIPHER_CIPHER=ZET/IJK
ZETCIPHER_ACCESS_KEY_ID=50454574382075219881774744823615123462103932128744
ZETCIPHER_ACCESS_KEY=ZET/88867456/zFkSyIzsaLFFi095l85xSfNmiGwwprAmWwV/7Ih0scM=
ZETCIPHER_SIGNING_SECRET=2636727
ZETCIPHER_TOKEN_LIFETIME=3600
```

### 🧠 Encode a Token
```php
$expires = now()->addMinutes(15)->getTimestamp();
$hash = ZetCipher::encode(data: $data, expires: $expires);
```

**Example Output:**
```php
8269924689234252895754188963109595788351614743579034711872120201135421543216429311624454
```

**Decode Example:**
```php
"Hello world, welcome to ZetCipher"
```

---

## 🔒 Advanced Usage

### Passphrase Encryption
```php
$token = ZetCipher::encode(
    data: $request->input('data'),
    expires: $expires,
    passphrase: $request->input('passphrase'),
);
```

### Passphrase Decoding
```php
$decoded = ZetCipher::decode(
    token: $request->input('data'),
    passphrase: $request->input('passphrase'),
);
```

### End-to-End Secure Parameters
Define your own **planet**, **coordinates**, and **passport** for additional uniqueness:
```php
$token = ZetCipher::decode(
    token: $request->input('data'),
    passphrase: $request->input('passphrase'),
    planet: $request->input('planet'),
    coordinates: $request->input('coordinate'),
    passport: $request->input('passport'),
);
```

---

## 🪐 Planet Codes
```php
$security_codes = [
  "ZET/ACS","ZET/DEF","ZET/GHI","ZET/JKL","ZET/MNO","ZET/PQR",
  "ZET/STU","ZET/VWX","ZET/YZZ","ZET/YZA","ZET/BCD","ZET/EFG",
  "ZET/HIJ","ZET/KLM","ZET/NOP","ZET/QRS","ZET/TUV","ZET/WXY",
  "ZET/ZAB","ZET/CDE","ZET/FGH","ZET/IJK","ZET/LMN","ZET/OPQ",
  "ZET/RST","ZET/UVW","ZET/XYZ","ZET/GHJ","ZET/ZAA","ZET/QRT",
  "ZET/STV","ZET/WXZ","ZET/YZB","ZET/BDE","ZET/FGI","ZET/HJL",
  "ZET/KMO","ZET/NPQ","ZET/RSU","ZET/TVW","ZET/WYa","ZET/YAB",
  "ZET/CDF","ZET/EGH","ZET/HIK","ZET/JLM","ZET/NPR","ZET/QST",
  "ZET/UVX","ZET/WYZ","ZET/ZAC","ZET/BCE","ZET/DFG","ZET/GIJ",
  "ZET/HKL","ZET/JMN","ZET/LNP","ZET/PQS","ZET/RTU","ZET/SVW",
  "ZET/UXY","ZET/ZAD","ZET/BEF","ZET/CGH","ZET/DIJ","ZET/EKL",
  "ZET/FMN","ZET/GOP","ZET/HQR","ZET/IST","ZET/JUV","ZET/KWX",
  "ZET/LYZ","ZET/MZA","ZET/NBC","ZET/ODE","ZET/PFG","ZET/QGH",
  "ZET/RHI","ZET/SIJ","ZET/TKL"
];
```

---

## ✍️ Signing and Verification

### Token Sign
```php
$token = ZetCipher::sign(); // user-only token
$token = ZetCipher::sign(passphrase: $request->input("pin"));
```

### Handshake Between Users
```php
$token = ZetCipher::handshake(id: $request->input("user_id"));
$token = ZetCipher::handshake(id: $request->input("user_id"), data: $request->input("message"));
```

### Verification
```php
$token = ZetCipher::verifyHandshake(token: $request->input("token"));
$token = ZetCipher::verifySign($request->token);
```

---

## ✅ Input Validation Example
```php
$rules = [
    'data'       => ['required','string','regex:/^[A-Za-z0-9\-]+$/'],
    'coordinate' => ['required','regex:/^\d+$/','integer','min:1'],
    'passport'   => ['required','integer','min:1','max:3628800'],   
    'passphrase' => ['nullable','string'],
    'planet'     => ['nullable','string'],
];

$messages = [
    'data.required'       => 'Data field is required.',
    'data.regex'          => 'Data can only contain letters, numbers, and dashes.',
    'coordinate.required' => 'Coordinates are required.',
    'coordinate.regex'    => 'Coordinates must be numeric.',
    'passport.required'   => 'Passport field is required.',
    'passport.integer'    => 'Passport must be an integer.',
    'passport.max'        => 'Passport cannot exceed 3,628,800.',
];
```

---

## 💡 Why ZetCipher?

ZetCipher introduces a **new cryptographic paradigm** — a **multi-layered, owner-tied encryption system** where:

- Output is **contextual** to each user and environment.  
- Tokens are **non-deterministic** and **cannot be precomputed**.  
- Security derives from **personalized mathematical mappings** (planet, coordinates, passport).  
- It anticipates **post-quantum threats** through abstract, owner-based security.

---

## 🧱 Core Features

- 🔢 **Pure Numeric Cipher:** Output is numeric-only, safe for URLs and external integrations.  
- 🗝 **Per-User Secret Key:** Tokens are user-specific and non-transferable.  
- 🌌 **Dynamic Planet & Coordinates:** Adds layered mathematical complexity.  
- ⏳ **TTL & Self-Destruct:** Supports time-limited and expiring tokens.  
- 🔒 **Optional Passphrase/PIN:** Additional manual encryption layer.  
- 🔄 **Multi-Layer Hashing:** Combines reversible and irreversible processes.  
- 🤝 **Handshake System:** Enables secure message exchange between users.  
- ✅ **User Signing & Verification:** Suitable for email/PIN validation.  
- 📏 **Built-In Validation:** Ensures clean and safe input structure.

---

## 🧪 Voluntary Security Testing Invitation

We welcome **researchers, developers, and contributors** to test ZetCipher’s resilience.  The goal is to **enhance security**, not to exploit vulnerabilities.

### Rules
- Use the open-source package locally.  
- If you discover unconventional decoding or sensitive data exposure, report it responsibly.  
- No monetary rewards — only **public contributor acknowledgment** on our official site.

### Reporting Format
Send to: [anonputraid@getbitlab.com](mailto:anonputraid@getbitlab.com)

```
Subject: [Zetcipher][VULN] <summary>

1) Summary of the finding  
2) Steps to reproduce (sandbox/local)  
3) Severity (Low/Medium/High/Critical)  
4) Proof of concept (minimal output, no sensitive data)  
5) Suggested mitigation (optional)
```

---

## 🧠 Final Thought

ZetCipher’s philosophy:  
> “A line on stone may look meaningless — until the one who drew it explains the universe behind it.”  
Security is not in the code or key length, but in the **mind and intent** that created it.

---
**📌 License:** Apache-2.0 
**📧 Author:** anonputraid
