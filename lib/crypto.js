/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const crypto = require("crypto");

const buf = require('buf');

const COOKIE_NAME_SEP = '=';
const KDF_ENC = 'cookiesession-encryption';
const KDF_MAC = 'cookiesession-signature';

/* map from cipher algorithm to exact key byte length */
const ENCRYPTION_ALGORITHMS = {
  aes128: 16, // implicit CBC mode
  aes192: 24,
  aes256: 32
};
const DEFAULT_ENCRYPTION_ALGO = 'aes256';

/* map from hmac algorithm to _minimum_ key byte length */
const SIGNATURE_ALGORITHMS = {
  'sha256': 32,
  'sha256-drop128': 32,
  'sha384': 48,
  'sha384-drop192': 48,
  'sha512': 64,
  'sha512-drop256': 64
};
const DEFAULT_SIGNATURE_ALGO = 'sha256';

function base64urlencode(arg) {
  var s = arg.toString('base64');
  s = s.split('=')[0]; // Remove any trailing '='s
  s = s.replace(/\+/g, '-'); // 62nd char of encoding
  s = s.replace(/\//g, '_'); // 63rd char of encoding
  // TODO optimize this; we can do much better
  return s;
}

function base64urldecode(arg) {
  var s = arg;
  s = s.replace(/-/g, '+'); // 62nd char of encoding
  s = s.replace(/_/g, '/'); // 63rd char of encoding
  switch (s.length % 4) { // Pad with trailing '='s
    case 0:
      break; // No pad chars in this case
    case 2:
      s += "==";
      break; // Two pad chars
    case 3:
      s += "=";
      break; // One pad char
    default:
      throw new Error("Illegal base64url string!");
  }
  return new Buffer(s, 'base64'); // Standard base64 decoder
}

function constantTimeEquals(a, b) {
  // Ideally this would be a native function, so it's less sensitive to how the
  // JS engine might optimize.
  if (a.length !== b.length) {
    return false;
  }
  var ret = 0;
  for (var i = 0; i < a.length; i++) {
    ret |= a.readUInt8(i) ^ b.readUInt8(i);
  }
  return ret === 0;
}

function deriveKey(master, type) {
  // eventually we want to use HKDF. For now we'll do something simpler.
  var hmac = crypto.createHmac('sha256', master);
  hmac.update(type);
  return buf(hmac.digest());
}

function setupKeys(opts) {
  // derive two keys, one for signing one for encrypting, from the secret.
  if (!opts.encryptionKey) {
    opts.encryptionKey = deriveKey(opts.secret, KDF_ENC);
  }

  if (!opts.signatureKey) {
    opts.signatureKey = deriveKey(opts.secret, KDF_MAC);
  }

  if (!opts.signatureAlgorithm) {
    opts.signatureAlgorithm = DEFAULT_SIGNATURE_ALGO;
  }

  if (!opts.encryptionAlgorithm) {
    opts.encryptionAlgorithm = DEFAULT_ENCRYPTION_ALGO;
  }
}

function keyConstraints(opts) {
  if (!Buffer.isBuffer(opts.encryptionKey)) {
    throw new Error('encryptionKey must be a Buffer');
  }
  if (!Buffer.isBuffer(opts.signatureKey)) {
    throw new Error('signatureKey must be a Buffer');
  }

  if (constantTimeEquals(opts.encryptionKey, opts.signatureKey)) {
    throw new Error('Encryption and Signature keys must be different');
  }

  var encAlgo = opts.encryptionAlgorithm.toLowerCase();
  var required = ENCRYPTION_ALGORITHMS[encAlgo];
  if (!required) {
    throw new Error('invalid encryptionAlgorithm, supported are: '+
                    Object.keys(ENCRYPTION_ALGORITHMS).join(', '));
  }
  if (opts.encryptionKey.length !== required) {
    throw new Error(
      'Encryption Key for '+encAlgo+' must be exactly '+required+' bytes '+
      '('+(required*8)+' bits)'
    );
  }

  var sigAlgo = opts.signatureAlgorithm.toLowerCase();
  var minimum = SIGNATURE_ALGORITHMS[sigAlgo];
  if (!minimum) {
    throw new Error('invalid signatureAlgorithm, supported are: '+
                    Object.keys(SIGNATURE_ALGORITHMS).join(', '));
  }
  if (opts.signatureKey.length < minimum) {
    throw new Error(
      'Encryption Key for '+sigAlgo+' must be at least '+minimum+' bytes '+
      '('+(minimum*8)+' bits)'
    );
  }
}


// it's good cryptographic pracitice to not leave buffers with sensitive
// contents hanging around.
function zeroBuffer(buf) {
  for (var i = 0; i < buf.length; i++) {
    buf[i] = 0;
  }
  return buf;
}

function hmacInit(algo, key) {
  var match = algo.match(/^([^-]+)(?:-drop(\d+))?$/);
  var baseAlg = match[1];
  var drop = match[2] ? parseInt(match[2], 10) : 0;

  var hmacAlg = crypto.createHmac(baseAlg, key);
  var origDigest = hmacAlg.digest;

  if (drop === 0) {
    // Before 0.10, crypto returns binary-encoded strings. Remove when dropping
    // 0.8 support.
    hmacAlg.digest = function() {
      return buf(origDigest.call(this));
    };
  } else {
    var N = drop / 8; // bits to bytes
    hmacAlg.digest = function dropN() {
      var result = buf(origDigest.call(this));
      // Throw away the second half of the 512-bit result, leaving the first
      // 256-bits.
      var truncated = new Buffer(N);
      result.copy(truncated, 0, 0, N);
      zeroBuffer(result);
      return truncated;
    };
  }

  return hmacAlg;
}

function computeHmac(opts, iv, ciphertext, duration, createdAt) {
  var hmacAlg = hmacInit(opts.signatureAlgorithm, opts.signatureKey);

  hmacAlg.update(iv);
  hmacAlg.update(".");
  hmacAlg.update(ciphertext);
  hmacAlg.update(".");
  hmacAlg.update(createdAt.toString());
  hmacAlg.update(".");
  hmacAlg.update(duration.toString());

  return hmacAlg.digest();
}

function encode(opts, content, duration, createdAt){
  // format will be:
  // iv.ciphertext.createdAt.duration.hmac

  if (!opts.cookieName) {
    throw new Error('cookieName option required');
  } else if (String(opts.cookieName).indexOf(COOKIE_NAME_SEP) !== -1) {
    throw new Error('cookieName cannot include "="');
  }

  setupKeys(opts);

  duration = duration || 24*60*60*1000;
  createdAt = createdAt || new Date().getTime();

  // generate iv
  var iv = crypto.randomBytes(16);

  // encrypt with encryption key
  var plaintext = new Buffer(
    opts.cookieName + COOKIE_NAME_SEP + JSON.stringify(content),
    'utf8'
  );
  var cipher = crypto.createCipheriv(
    opts.encryptionAlgorithm,
    opts.encryptionKey,
    iv
  );

  var ciphertextStart = buf(cipher.update(plaintext));
  zeroBuffer(plaintext);
  var ciphertextEnd = buf(cipher.final());
  var ciphertext = Buffer.concat([ciphertextStart, ciphertextEnd]);
  zeroBuffer(ciphertextStart);
  zeroBuffer(ciphertextEnd);

  // hmac it
  var hmac = computeHmac(opts, iv, ciphertext, duration, createdAt);

  var result = [
    base64urlencode(iv),
    base64urlencode(ciphertext),
    createdAt,
    duration,
    base64urlencode(hmac)
  ].join('.');

  zeroBuffer(iv);
  zeroBuffer(ciphertext);
  zeroBuffer(hmac);

  return result;
}

function decode(opts, content) {
  if (!opts.cookieName) {
    throw new Error("cookieName option required");
  }

  // stop at any time if there's an issue
  var components = content.split(".");
  if (components.length !== 5) {
    return;
  }

  setupKeys(opts);

  var iv;
  var ciphertext;
  var hmac;

  try {
    iv = base64urldecode(components[0]);
    ciphertext = base64urldecode(components[1]);
    hmac = base64urldecode(components[4]);
  } catch (ignored) {
    cleanup();
    return;
  }

  var createdAt = parseInt(components[2], 10);
  var duration = parseInt(components[3], 10);

  function cleanup() {
    if (iv) {
      zeroBuffer(iv);
    }

    if (ciphertext) {
      zeroBuffer(ciphertext);
    }

    if (hmac) {
      zeroBuffer(hmac);
    }

    if (expectedHmac) { // declared below
      zeroBuffer(expectedHmac);
    }
  }

  // make sure IV is right length
  if (iv.length !== 16) {
    cleanup();
    return;
  }

  // check hmac
  var expectedHmac = computeHmac(opts, iv, ciphertext, duration, createdAt);

  if (!constantTimeEquals(hmac, expectedHmac)) {
    cleanup();
    return;
  }

  // decrypt
  var cipher = crypto.createDecipheriv(
    opts.encryptionAlgorithm,
    opts.encryptionKey,
    iv
  );
  var plaintext = cipher.update(ciphertext, 'binary', 'utf8');
  plaintext += cipher.final('utf8');

  var cookieName = plaintext.substring(0, plaintext.indexOf(COOKIE_NAME_SEP));
  if (cookieName !== opts.cookieName) {
    cleanup();
    return;
  }

  var result;
  try {
    result = {
      content: JSON.parse(
        plaintext.substring(plaintext.indexOf(COOKIE_NAME_SEP) + 1)
      ),
      createdAt: createdAt,
      duration: duration
    };
  } catch (ignored) {
  }

  cleanup();
  return result;
}

exports.encode = encode;
exports.decode = decode;
exports._setupKeys = setupKeys;
exports._keyConstraints = keyConstraints;
exports.computeHmac = computeHmac;
