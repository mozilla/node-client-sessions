
var Cookies = require("cookies");
var Proxy = require("node-proxy");
var Handler = require("./ProxyHandler.js");
var crypto = require("crypto");

function base64urlencode(arg) {
  var s = new Buffer(arg).toString('base64');
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
  switch (s.length % 4) // Pad with trailing '='s
  {
  case 0: break; // No pad chars in this case
  case 2: s += "=="; break; // Two pad chars
  case 3: s += "="; break; // One pad char
  default: throw new InputException("Illegal base64url string!");
  }
  return new Buffer(s, 'base64').toString('ascii'); // Standard base64 decoder
}

/*
 * Session object
 *
 * this should be implemented with proxies at some point
 */
function Session(req, res, cookies, opts) {
  this.req = req;
  this.res = res;
  this.cookies = cookies;
  this.opts = opts;
  this.content = {};
  this.loaded = false;
  this.dirty = false;
}

Session.prototype = {
  clear: function() {
    this.content = {};
    this.updateCookie();
  },

  setExpires: function(numSeconds) {
  },

  // take the content and do the encrypt-and-sign
  box: function() {
    // format will be:
    // iv.ciphertext.hmac

    // generate iv
    var iv = crypto.randomBytes(16).toString('binary');
    
    // encrypt with encryption key
    var cipher = crypto.createCipheriv('aes256', this.opts.encryptionKey, iv);
    var ciphertext = cipher.update(JSON.stringify(this.content));
    ciphertext += cipher.final();

    // hmac it
    var hmacAlg = crypto.createHmac('sha256', this.opts.signatureKey);
    hmacAlg.update(ciphertext);
    var hmac = hmacAlg.digest();

    return base64urlencode(iv) + "." + base64urlencode(ciphertext) + "." +base64urlencode(hmac);
  },

  unbox: function(content) {
    this.content = {};

    // stop at any time if there's an issue

    var components = content.split(".");
    if (components.length != 3)
      return;

    // check hmac
    var ciphertext = base64urldecode(components[1]);
    var hmac = base64urldecode(components[2]);
    var hmacAlg = crypto.createHmac('sha256', this.opts.signatureKey);
    hmacAlg.update(ciphertext);
    var expected_hmac = hmacAlg.digest();
    if (hmac != expected_hmac)
      return;

    // decrypt
    var iv = base64urldecode(components[0]);
    var cipher = crypto.createDecipheriv('aes256', this.opts.encryptionKey, iv);
    var plaintext = cipher.update(ciphertext);
    plaintext += cipher.final();
    
    try {
      this.content = JSON.parse(plaintext);      
    } catch (x) {
      this.content = {};
    }
  },
  
  updateCookie: function() {
    if (this.dirty)
      this.cookies.set(this.opts.cookieName, this.box(), this.opts.cookie);
  },

  loadFromCookie: function() {
    var cookie = this.cookies.get(this.opts.cookieName);
    if (cookie) {
      this.unbox(cookie);
    } else {
      this.content = {};
    }

    this.loaded = true;
  },
  
  // called to create a proxy that monitors the session
  // for new properties being set
  monitor: function() {
    // set up proxies
    var sessionHandler = new Handler(this);

    // all values from content except special values
    sessionHandler.get = function(rcvr, name) {
      if (['clear', 'setExpires'].indexOf(name) > -1) {
        return this.target[name].bind(this.target);
      } else {
        if (!this.target.loaded)
          this.target.loadFromCookie();
        return this.target.content[name];
      }
    };

    // set all values to content
    sessionHandler.set = function(rcvr, name, value) {
      // we have to load existing content, otherwise it will later override
      // the content that is written.
      if (!this.target.loaded)
        this.target.loadFromCookie();
      
      this.target.content[name] = value;
      this.target.dirty = true;
    };
    
    var proxySession = Proxy.create(sessionHandler);
    return proxySession;
  }
};


function deriveKey(master, type) {
  var hmac = crypto.createHmac('sha256', master);
  hmac.update(type);
  return hmac.digest('binary');
}

var cookieSession = function(opts) {
  if (!opts.secret)
    throw "cannot set up sessions without a secret";
  
  opts.cookieName = opts.cookieName || "session";

  // derive two keys, one for signing one for encrypting, from the secret.
  // eventually we want to use HKDF. For now we'll do something simpler.
  opts.encryptionKey = deriveKey(opts.secret, 'cookiesession-encryption');
  opts.signatureKey = deriveKey(opts.secret, 'cookiesession-signature');
  
  return function(req, res, next) {
    var cookies = new Cookies(req, res);
    var raw_session = new Session(req, res, cookies, opts);
    req.session = raw_session.monitor();

    // I wish we didn't have to do things this way, but
    // I can find no other way of delaying the setting of
    // the cookie until the end
    var oldWriteHead = res.writeHead;
    res.writeHead = function() {
      raw_session.updateCookie();

      oldWriteHead.apply(this, arguments);
    };    

    next();
  };
};

module.exports = cookieSession;