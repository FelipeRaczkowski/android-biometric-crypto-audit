# Android Biometric Authentication Review Toolkit

A small, focused toolkit for reviewing how Android apps implement biometric
authentication — and, specifically, whether that biometry is **cryptographically
bound** or just a bypassable boolean check.

It pairs **static triage** (Semgrep) with **runtime confirmation** (Frida),
because the most interesting biometric flaw — a `CryptoObject` that exists but is
never actually used — cannot be seen by static analysis alone. Every rule and
hook maps to [OWASP MASTG-BEST-0036](https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0036/)
(bind biometric authentication to a keystore operation).

```
biometric-rules.yml   # 7 Semgrep rules — static triage over jadx-decompiled Java
biometric_probe.js    # Frida probe   — runtime confirmation of the actual flow
```

---

## The problem

A secure Android biometric flow binds the prompt to a cryptographic operation:

1. a key is generated in the `AndroidKeyStore` with `setUserAuthenticationRequired(true)`;
2. a `Cipher`/`Signature`/`Mac` is initialised with that key;
3. it is wrapped in a `CryptoObject` and passed to `BiometricPrompt.authenticate(promptInfo, cryptoObject)`;
4. `onAuthenticationSucceeded` **uses** `result.getCryptoObject()` (e.g. `doFinal`).

If the key does not require authentication, if no `CryptoObject` is passed, or if
the callback **ignores the result**, success is just a callback firing — and an
attacker who forces `onAuthenticationSucceeded` (Frida) walks straight in.

The subtlest failure is the fourth one: a valid `CryptoObject` is passed but never
consumed. The crypto is **decorative**. Static analysis sees the `CryptoObject` and
assumes the flow is sound; only runtime shows the `Cipher` is never touched.

---

## Methodology

```
jadx (decompile)  ->  scope to the app's code  ->  Semgrep (static triage)  ->  Frida (runtime confirmation)
```

1. **Decompile** the APK to Java with `jadx`.
2. **Scope** the scan to the app's own packages (see *Scoping* below) — a
   decompiled APK bundles the whole dependency tree.
3. **Triage statically** with the Semgrep ruleset: fast, finds candidates, maps to
   a standard.
4. **Confirm dynamically** with the Frida probe: resolves what static cannot —
   whether the crypto binding is real.

Static narrows the search; dynamic proves the finding. Neither is sufficient alone.

---

## 1. Semgrep ruleset (`biometric-rules.yml`)

Run over the decompiled sources:

```bash
jadx -d out app.apk
semgrep --config biometric-rules.yml out/sources
```

| ID | Severity | CWE | What it finds |
|----|----------|-----|---------------|
| `biometric-key-auth-not-required` | HIGH | CWE-287 | `setUserAuthenticationRequired(false)` — key usable with no auth |
| `biometric-authenticate-without-cryptoobject` | HIGH | CWE-287 | `authenticate()` with no `CryptoObject` (androidx **and** native) — event-bound |
| `biometric-weak-authenticator` | MEDIUM | CWE-287 | `setAllowedAuthenticators` allows `BIOMETRIC_WEAK` / `DEVICE_CREDENTIAL` (matches inlined integer bitmasks) |
| `biometric-auth-validity-time-window` | MEDIUM | CWE-287 | positive `setUserAuthenticationValidityDurationSeconds` / `setUserAuthenticationParameters` timeout — time-bound, not per-use |
| `biometric-not-invalidated-on-enrollment` | MEDIUM | CWE-287 | `setInvalidatedByBiometricEnrollment(false)` — key survives a new enrollment |
| `biometric-deprecated-fingerprintmanager` | LOW | CWE-477 | use of the deprecated `FingerprintManager` |
| `biometric-key-auth-flag-absent` | INFO | CWE-522 | KeyStore key built with no `setUserAuthenticationRequired` at all — **inventory**, triage which keys should be biometric |

Design notes that matter:

- **Three builder shapes.** The key-generation rule anchors on the
  `KeyGenParameterSpec.Builder` construction and suppresses it only when the
  enclosing method configures authentication — so it catches the fluent single-call,
  fluent multi-call, and split-across-statements forms equally.
- **Two biometric APIs.** `androidx.biometric.BiometricPrompt` and the native
  `android.hardware.biometrics.BiometricPrompt` have different `authenticate`
  signatures, the rules cover both.
- **Inlined constants.** In a decompiled APK the `Authenticators` constants are
  integers, not symbolic names, so the weak-authenticator rule matches the integer
  bitmask (`DEVICE_CREDENTIAL` bit set, or low byte `0xFF`).

---

## 2. Frida probe (`biometric_probe.js`)

Confirms at runtime what static cannot: whether the `CryptoObject` is actually used.

```bash
# spawn (most reliable — hooks are in place before onCreate)
frida -U -f <package> -l biometric_probe.js

# or attach from a screen BEFORE the biometric one, then navigate in
frida -U -n <process_name> -l biometric_probe.js
```

It hooks the key builder, the prompt configuration, both `authenticate` APIs, the
deprecated `FingerprintManager`, and — the key part — it **captures the app's real
callback instance** (apps subclass and override `onAuthenticationSucceeded`, so
hooking the base class does not intercept it) and checks whether a crypto operation
actually runs inside it.

Output format: `[tag] [what was found in the code] --> plain-language verdict`

```
[+] [androidx authenticate(PromptInfo, CryptoObject)] --> crypto-bound call carrying Cipher
[!] [VulnerableActivity$1.onAuthenticationSucceeded] --> CryptoObject present but never used, decorative crypto, bypassable
```

`[+]` expected/secure  ·  `[!]` finding/insecure  ·  `[*]` info.

---

## Scoping

A decompiled APK contains the whole dependency tree, so run the ruleset against the
app's own code, not the bundled libraries:

```bash
# readable package names — include the app's roots
semgrep --config biometric-rules.yml --include 'com/yourapp/**' out/sources

# obfuscated app — exclude the framework roots instead
semgrep --config biometric-rules.yml \
  --exclude androidx --exclude kotlin --exclude 'com/google' out/sources
```

The rules deliberately contain **no** package denylist: scope is the analyst's
decision, not something baked into (and rotting inside) every rule.

---

## Limitations (by design)

- **Decompilation-bound.** The static rules only see what jadx can reconstruct.
  A heavily obfuscated / protected app (DexGuard, anti-instrumentation) can defeat
  both the decompiler and the Frida hooks.
- **Static is syntactic, not dataflow.** It flags candidates; it does not follow a
  key from generation to use. The `key-auth-flag-absent` rule is therefore an
  **inventory** (INFO), not a verdict — hence the Frida step.
- **Literal-only comparisons.** Rules that compare values (authenticators,
  timeouts) evaluate literals; a value passed through a variable is a known false
  negative — confirm it at runtime.
- **This is a triage aid, not a vulnerability scanner.** Hits are reviewed by a
  human; the toolkit makes that review fast and grounded in a standard.

---

## Standards

Every rule and hook maps to **OWASP MASVS-AUTH** and **MASTG-BEST-0036**
(*Testing Biometric Authentication* / cryptographic binding of local authentication).

---

## Note

This probe is diagnostic: it reports whether a biometric flow is cryptographically
bound or bypassable, with evidence. It does not ship an exploit. Actively forcing
`onAuthenticationSucceeded` to walk through an event-bound flow is trivial and
already well documented, and is intentionally left out here — the detection above
is the point, and the finding stands on its own without a push-button bypass. Use
the toolkit only against apps you are authorised to test (your own apps, a
sanctioned engagement, or intentionally vulnerable training targets).
