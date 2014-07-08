/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const Cookies = require('cookies');

const crypto = require('./crypto');
const keyConstraints = crypto._keyConstraints;
const setupKeys = crypto._setupKeys;
const Session = require('./session');

const DURATION = 24 * 60 * 60 * 1000; //24hours
const ACTIVE_DURATION = 1000 * 60 * 5; //5mins

function isObject(val) {
  return Object.prototype.toString.call(val) === '[object Object]';
}

function config(opts) {
  if (!opts) {
    throw new Error("no options provided, some are required");
  }

  if (!(opts.secret || (opts.encryptionKey && opts.signatureKey))) {
    throw new Error("cannot set up sessions without a secret "+
                    "or encryptionKey/signatureKey pair");
  }

  // defaults
  opts.cookieName = opts.cookieName || "session_state";
  opts.duration = opts.duration || DURATION;
  opts.activeDuration = 'activeDuration' in opts ?
    opts.activeDuration : ACTIVE_DURATION;

  // set up cookie defaults
  opts.cookie = opts.cookie || {};
  if (typeof opts.cookie.httpOnly === 'undefined') {
    opts.cookie.httpOnly = true;
  }

  // let's not default to secure just yet,
  // as this depends on the socket being secure,
  // which is tricky to determine if proxied.
  /*
  if (typeof(opts.cookie.secure) == 'undefined')
    opts.cookie.secure = true;
    */

  setupKeys(opts);
  keyConstraints(opts);
  opts._propertyName = opts.requestKey || opts.cookieName;
}

function session(host, req, res, opts) {
  var propertyName = opts._propertyName;
  if (propertyName in req) {
    return; //self aware
  }

  var cookies = new Cookies(req, res);
  var rawSession = new Session(req, res, cookies, opts);
  Object.defineProperty(host, propertyName, {
    get: function getSession() {
      return rawSession.content;
    },
    set: function setSession(value) {
      if (isObject(value)) {
        rawSession.content = value;
      } else {
        throw new TypeError("cannot set client-session to non-object");
      }
    }
  });
  return rawSession;
}

module.exports = function clientSessionFactory(opts) {

  config(opts);

  return function clientSession(req, res, next) {

    var rawSession;
    try {
      rawSession = session(req, req, res, opts);
    } catch (x) {
      // this happens only if there's a big problem
      process.nextTick(function() {
        next("client-sessions error: " + x.toString());
      });
      return;
    }
    if (!rawSession) {
      // self-awared
      return next();
    }

    var writeHead = res.writeHead;
    res.writeHead = function () {
      rawSession.updateCookie();
      return writeHead.apply(res, arguments);
    };

    next();
  };
};

module.exports.config = config;
module.exports.session = session;
