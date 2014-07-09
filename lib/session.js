/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const crypto = require('./crypto');
const decode = crypto.decode;
const encode = crypto.encode;

/*
 * Session object
 */
function Session(req, res, cookies, opts) {
  this.req = req;
  this.res = res;
  this.cookies = cookies;
  this.opts = opts;
  if (opts.cookie.ephemeral && opts.cookie.maxAge) {
    throw new Error("you cannot have an ephemeral cookie with a maxAge.");
  }

  this.content = {};
  this.json = JSON.stringify(this._content);
  this.loaded = false;
  this.dirty = false;

  // no need to initialize it, loadFromCookie will do
  // via reset() or unbox()
  this.createdAt = null;
  this.duration = opts.duration;
  this.activeDuration = opts.activeDuration;

  // support for maxAge
  if (opts.cookie.maxAge) {
    this.expires = new Date(new Date().getTime() + opts.cookie.maxAge);
  } else {
    this.updateDefaultExpires();
  }

  // here, we check that the security bits are set correctly
  var secure = (res.socket && res.socket.encrypted) ||
      (req.connection && req.connection.proxySecure);
  if (opts.cookie.secure && !secure) {
    throw new Error("you cannot have a secure cookie unless the socket is " +
        " secure or you declare req.connection.proxySecure to be true.");
  }
}

Session.prototype = {
  updateDefaultExpires: function() {
    if (this.opts.cookie.maxAge) {
      return;
    }

    if (this.opts.cookie.ephemeral) {
      this.expires = null;
    } else {
      var time = this.createdAt || new Date().getTime();
      // the cookie should expire when it becomes invalid
      // we add an extra second because the conversion to a date
      // truncates the milliseconds
      this.expires = new Date(time + this.duration + 1000);
    }
  },

  clearContent: function(keysToPreserve) {
    var self = this;
    Object.keys(this._content).forEach(function(k) {
      // exclude this key if it's meant to be preserved
      if (keysToPreserve && (keysToPreserve.indexOf(k) > -1)) {
        return;
      }

      delete self._content[k];
    });
  },

  reset: function(keysToPreserve) {
    this.clearContent(keysToPreserve);
    this.createdAt = new Date().getTime();
    this.duration = this.opts.duration;
    this.updateDefaultExpires();
    this.dirty = true;
    this.loaded = true;
  },

  setDuration: function(newDuration, ephemeral) {
    if (ephemeral && this.opts.cookie.maxAge) {
      throw new Error("you cannot have an ephemeral cookie with a maxAge.");
    }
    if (!this.loaded) {
      this.loadFromCookie(true);
    }
    this.dirty = true;
    this.duration = newDuration;
    this.createdAt = new Date().getTime();
    this.opts.cookie.ephemeral = ephemeral;
    this.updateDefaultExpires();
  },

  // take the content and do the encrypt-and-sign
  // boxing builds in the concept of createdAt
  box: function() {
    return encode(this.opts, this._content, this.duration, this.createdAt);
  },

  unbox: function(content) {
    this.clearContent();

    var unboxed = decode(this.opts, content);
    if (!unboxed) {
      return;
    }

    var self = this;


    Object.keys(unboxed.content).forEach(function(k) {
      self._content[k] = unboxed.content[k];
    });

    this.createdAt = unboxed.createdAt;
    this.duration = unboxed.duration;
    this.updateDefaultExpires();
  },

  updateCookie: function() {
    if (this.isDirty()) {
      // support for adding/removing cookie expires
      this.opts.cookie.expires = this.expires;

      try {
        this.cookies.set(this.opts.cookieName, this.box(), this.opts.cookie);
      } catch (x) {
        // this really shouldn't happen. Right now it happens if secure is set
        // but cookies can't determine that the connection is secure.
      }
    }
  },

  loadFromCookie: function(forceReset) {
    var cookie = this.cookies.get(this.opts.cookieName);
    if (cookie) {
      this.unbox(cookie);

      var expiresAt = this.createdAt + this.duration;
      var now = Date.now();
      // should we reset this session?
      if (expiresAt < now) {
        this.reset();
      // if expiration is soon, push back a few minutes to not interrupt user
      } else if (expiresAt - now < this.activeDuration) {
        this.createdAt += this.activeDuration;
        this.dirty = true;
        this.updateDefaultExpires();
      }
    } else {
      if (forceReset) {
        this.reset();
      } else {
        return false; // didn't actually load the cookie
      }
    }

    this.loaded = true;
    this.json = JSON.stringify(this._content);
    return true;
  },

  isDirty: function() {
    return this.dirty || (this.json !== JSON.stringify(this._content));
  }

};

Object.defineProperty(Session.prototype, 'content', {
  get: function getContent() {
    if (!this.loaded) {
      this.loadFromCookie();
    }
    return this._content;
  },
  set: function setContent(value) {
    Object.defineProperty(value, 'reset', {
      enumerable: false,
      value: this.reset.bind(this)
    });
    Object.defineProperty(value, 'setDuration', {
      enumerable: false,
      value: this.setDuration.bind(this)
    });
    this._content = value;
  }
});

module.exports = Session;
