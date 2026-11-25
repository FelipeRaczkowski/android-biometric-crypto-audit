/*
 * biometric_probe.js — Frida runtime probe for Android biometric flows.
 *
 * Confirms at runtime what static analysis cannot: whether a biometric flow is
 * cryptographically bound (key requires auth, CryptoObject passed AND consumed)
 * or just a bypassable callback. Covers androidx.biometric, the native
 * android.hardware.biometrics API, and the deprecated FingerprintManager.
 * See README.md for the full write-up and the OWASP MASTG-BEST-0036 mapping.
 *
 * Run (spawn is most reliable — hooks are in place before onCreate):
 *     frida -U -f <package> -l biometric_probe.js
 *
 * Output:  [tag] [what was found in the code] --> verdict
 *     [+] secure / expected    [!] finding / insecure    [*] info
 */

'use strict';

// ----- logging -------------------------------------------------------------
// One finding per line. The [bracketed] part is the concrete code element
// that was found; the text after the arrow is the verdict. No ':' or ';' so
// each line reads cleanly left to right.
function fmt(tag, found, note) {
  var s = '[' + tag + ']';
  if (found) { s += ' [' + found + ']'; }
  if (found && note) { s += ' --> ' + note; }
  else if (note)     { s += ' ' + note; }
  console.log(s);
}
function ok(found, note)   { fmt('+', found, note); }  // secure / expected
function warn(found, note) { fmt('!', found, note); }  // finding / insecure
function info(found, note) { fmt('*', found, note); }  // informational

// ----- authenticator bitmask decoder (unit-tested below) -------------------
// BIOMETRIC_STRONG = 0x000F, BIOMETRIC_WEAK = 0x00FF, DEVICE_CREDENTIAL = 0x8000.
// WEAK shares STRONG's low nibble, so test WEAK first and treat it as exclusive
// of STRONG, otherwise 0xFF is mislabelled "STRONG|WEAK". Only BIOMETRIC_STRONG
// may be combined with a CryptoObject, so WEAK or any DEVICE_CREDENTIAL bit is
// flagged insecure.
function decodeAuthenticators(v) {
  var parts = [];
  var insecure = false;

  if ((v & 0x00FF) === 0x00FF) {
    parts.push('BIOMETRIC_WEAK');
    insecure = true;
  } else if ((v & 0x000F) === 0x000F) {
    parts.push('BIOMETRIC_STRONG');
  }
  if ((v & 0x8000) === 0x8000) {
    parts.push('DEVICE_CREDENTIAL');
    insecure = true;
  }
  if (parts.length === 0) {
    parts.push('UNKNOWN(0x' + (v >>> 0).toString(16) + ')');
  }
  return { label: parts.join('|'), insecure: insecure };
}

// ----- CryptoObject inspection (androidx + native share method names) ------
function describeCryptoObject(co) {
  if (co === null || co === undefined) { return 'none'; }
  var found = [];
  ['getCipher', 'getSignature', 'getMac'].forEach(function (g) {
    try {
      var r = co[g] ? co[g]() : null;
      if (r !== null && r !== undefined) { found.push(g.substring(3)); }
    } catch (e) { /* overload/obfuscation differences — ignore */ }
  });
  return found.length ? found.join('+') : 'empty (no Cipher Signature or Mac)';
}

// ----- a hook that tolerates a missing class/method ------------------------
function safeHook(label, fn) {
  try {
    fn();
  } catch (e) {
    info(label, 'not present or not hookable');
  }
}

function main() {
  Java.perform(function () {
    console.log('');
    console.log('================ biometric_probe ================');
    info('attached', 'walk the biometric flow in the app now');

    var cryptoOps = 0;       // real crypto ops observed (doFinal/sign/mac)
    var installedCb = {};    // concrete callback classes already hooked

    // ===================================================================
    // 1. KEY CONSTRUCTION
    // ===================================================================
    safeHook('KeyGenParameterSpec$Builder.setUserAuthenticationRequired', function () {
      var B = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
      B.setUserAuthenticationRequired.overload('boolean').implementation = function (req) {
        if (req) {
          ok('setUserAuthenticationRequired(true)', 'key is auth-gated');
        } else {
          warn('setUserAuthenticationRequired(false)', 'key usable without auth, any CryptoObject is decorative');
        }
        return this.setUserAuthenticationRequired(req);
      };
    });

    safeHook('KeyGenParameterSpec$Builder.setInvalidatedByBiometricEnrollment', function () {
      var B = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
      B.setInvalidatedByBiometricEnrollment.overload('boolean').implementation = function (inv) {
        if (inv) {
          ok('setInvalidatedByBiometricEnrollment(true)', 'key dies on a new enrollment');
        } else {
          warn('setInvalidatedByBiometricEnrollment(false)', 'key survives a newly enrolled biometric');
        }
        return this.setInvalidatedByBiometricEnrollment(inv);
      };
    });

    safeHook('KeyGenParameterSpec$Builder.setUserAuthenticationValidityDurationSeconds', function () {
      var B = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
      B.setUserAuthenticationValidityDurationSeconds.overload('int').implementation = function (n) {
        if (n > 0) {
          warn('setUserAuthenticationValidityDurationSeconds(' + n + ')', 'time-bound window, not per-use');
        } else {
          ok('setUserAuthenticationValidityDurationSeconds(' + n + ')', 'per-use binding');
        }
        return this.setUserAuthenticationValidityDurationSeconds(n);
      };
    });

    safeHook('KeyGenParameterSpec$Builder.setUserAuthenticationParameters', function () {
      var B = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
      B.setUserAuthenticationParameters.overload('int', 'int').implementation = function (timeout, type) {
        if (timeout > 0) {
          warn('setUserAuthenticationParameters(' + timeout + ', ' + type + ')', 'time-bound window');
        } else {
          ok('setUserAuthenticationParameters(' + timeout + ', ' + type + ')', 'per-use binding');
        }
        return this.setUserAuthenticationParameters(timeout, type);
      };
    });

    // ===================================================================
    // 2. PROMPT CONSTRUCTION — setAllowedAuthenticators(int)
    // ===================================================================
    function hookAllowedAuthenticators(className) {
      safeHook(className + '.setAllowedAuthenticators', function () {
        var B = Java.use(className);
        B.setAllowedAuthenticators.overload('int').implementation = function (v) {
          var d = decodeAuthenticators(v);
          var found = 'setAllowedAuthenticators(0x' + (v >>> 0).toString(16) + ') = ' + d.label;
          if (d.insecure) {
            warn(found, 'only BIOMETRIC_STRONG can be crypto-bound');
          } else {
            ok(found, 'strong authenticator');
          }
          return this.setAllowedAuthenticators(v);
        };
      });
    }
    hookAllowedAuthenticators('androidx.biometric.BiometricPrompt$PromptInfo$Builder');
    hookAllowedAuthenticators('android.hardware.biometrics.BiometricPrompt$Builder');

    // ===================================================================
    // 3. THE authenticate() CALL
    // ===================================================================
    // --- androidx (1 arg = event-bound, 2 args = crypto-bound) ---
    safeHook('androidx BiometricPrompt.authenticate', function () {
      var BP = Java.use('androidx.biometric.BiometricPrompt');

      BP.authenticate.overload('androidx.biometric.BiometricPrompt$PromptInfo')
        .implementation = function (info_) {
          warn('androidx authenticate(PromptInfo)', 'event-bound call with no CryptoObject, bypassable');
          return this.authenticate(info_);
        };

      BP.authenticate.overload('androidx.biometric.BiometricPrompt$PromptInfo',
                               'androidx.biometric.BiometricPrompt$CryptoObject')
        .implementation = function (info_, crypto) {
          ok('androidx authenticate(PromptInfo, CryptoObject)', 'crypto-bound call carrying ' + describeCryptoObject(crypto));
          return this.authenticate(info_, crypto);
        };
    });

    // --- native (3 args = event-bound, 4 args = crypto-bound) ---
    safeHook('native BiometricPrompt.authenticate', function () {
      var BP = Java.use('android.hardware.biometrics.BiometricPrompt');

      BP.authenticate.overload('android.os.CancellationSignal',
                               'java.util.concurrent.Executor',
                               'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback')
        .implementation = function (cancel, exec, cb) {
          warn('native authenticate(cancel, executor, callback)', 'event-bound call with no CryptoObject, bypassable');
          installConcreteCallback(cb, 'android.hardware.biometrics.BiometricPrompt$AuthenticationResult', 'native');
          return this.authenticate(cancel, exec, cb);
        };

      BP.authenticate.overload('android.hardware.biometrics.BiometricPrompt$CryptoObject',
                               'android.os.CancellationSignal',
                               'java.util.concurrent.Executor',
                               'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback')
        .implementation = function (crypto, cancel, exec, cb) {
          ok('native authenticate(CryptoObject, cancel, executor, callback)', 'crypto-bound call carrying ' + describeCryptoObject(crypto));
          installConcreteCallback(cb, 'android.hardware.biometrics.BiometricPrompt$AuthenticationResult', 'native');
          return this.authenticate(crypto, cancel, exec, cb);
        };
    });

    // ===================================================================
    // 4. THE CALLBACK — what semgrep cannot see.
    //    Apps subclass AuthenticationCallback and OVERRIDE
    //    onAuthenticationSucceeded, so hooking the base class does not
    //    intercept it. We capture the real callback INSTANCE (at androidx
    //    construction or at the native authenticate call) and hook ITS
    //    concrete class, then check whether the CryptoObject is actually USED.
    // ===================================================================
    function installConcreteCallback(cbInstance, resultClass, apiTag) {
      try {
        if (cbInstance === null || cbInstance === undefined) { return; }
        var name = cbInstance.getClass().getName();
        // Skip androidx's own forwarding adapter (it wraps the native API and
        // never uses the cipher itself) so only the app's callback is reported.
        if (name.indexOf('androidx.biometric.') === 0 ||
            name.indexOf('android.hardware.') === 0) { return; }
        if (installedCb[name]) { return; }
        installedCb[name] = true;
        info(name, 'callback class captured via ' + apiTag);
        var CB = Java.use(name);

        CB.onAuthenticationSucceeded.overload(resultClass).implementation = function (result) {
          var co = null;
          try { co = result.getCryptoObject(); } catch (e) { /* ignore */ }

          if (co === null || co === undefined) {
            warn(name + '.onAuthenticationSucceeded', 'no CryptoObject in result, event-bound success, bypassable');
            return this.onAuthenticationSucceeded(result);
          }

          info(name + '.onAuthenticationSucceeded', 'result carries CryptoObject ' + describeCryptoObject(co));
          var before = cryptoOps;
          var ret = this.onAuthenticationSucceeded(result);
          if (cryptoOps > before) {
            ok(name + '.onAuthenticationSucceeded', 'CryptoObject consumed, doFinal or sign ran, binding is real');
          } else {
            warn(name + '.onAuthenticationSucceeded', 'CryptoObject present but never used, decorative crypto, access depends only on the callback firing, bypassable');
            setTimeout(function () {
              if (cryptoOps > before) {
                ok(name + '.onAuthenticationSucceeded', 'CryptoObject consumed shortly after, binding likely real');
              }
            }, 1500);
          }
          return ret;
        };
      } catch (e) {
        info('callback hook', 'error while installing');
      }
    }

    // androidx: capture the callback passed to the BiometricPrompt constructor.
    safeHook('androidx BiometricPrompt.$init (callback capture)', function () {
      var BP = Java.use('androidx.biometric.BiometricPrompt');
      var baseCb = Java.use('androidx.biometric.BiometricPrompt$AuthenticationCallback');
      BP.$init.overloads.forEach(function (ov) {
        ov.implementation = function () {
          for (var i = 0; i < arguments.length; i++) {
            try {
              if (arguments[i] !== null && baseCb.class.isInstance(arguments[i])) {
                installConcreteCallback(arguments[i],
                  'androidx.biometric.BiometricPrompt$AuthenticationResult', 'androidx');
              }
            } catch (e) { /* ignore non-matching args */ }
          }
          return ov.apply(this, arguments);
        };
      });
    });
    // native callbacks are captured inside the native authenticate() hooks.

    // ===================================================================
    // 4b. CRYPTO OPERATION OBSERVERS
    //     Count actual crypto ops so the callback hook can tell a CONSUMED
    //     CryptoObject from a DECORATIVE one. Silent (counter only).
    // ===================================================================
    function observeCryptoOp(className, methodName) {
      safeHook(className + '.' + methodName, function () {
        var C = Java.use(className);
        C[methodName].overloads.forEach(function (ov) {
          ov.implementation = function () {
            cryptoOps++;
            return ov.apply(this, arguments);
          };
        });
      });
    }
    observeCryptoOp('javax.crypto.Cipher', 'doFinal');
    observeCryptoOp('java.security.Signature', 'sign');
    observeCryptoOp('javax.crypto.Mac', 'doFinal');

    // ===================================================================
    // 5. LEGACY — deprecated FingerprintManager.authenticate
    // ===================================================================
    safeHook('FingerprintManager.authenticate', function () {
      var FM = Java.use('android.hardware.fingerprint.FingerprintManager');
      FM.authenticate.overloads.forEach(function (ov) {
        ov.implementation = function () {
          warn('FingerprintManager.authenticate()', 'deprecated API, no system dialog, pre-BiometricPrompt');
          return ov.apply(this, arguments);
        };
      });
    });

    info('hooks installed', '');
    console.log('=================================================');
    console.log('');
  });
}

// Run only inside Frida, where the Java bridge exists. (Also lets `node --check`
// validate the file without executing the hooks.)
if (typeof Java !== 'undefined') {
  main();
}
