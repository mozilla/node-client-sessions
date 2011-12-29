
var Cookies = require("cookies");
var Proxy = require("node-proxy");
var Handler = require("./ProxyHandler.js");

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
}

Session.prototype = {
  clear: function() {
  },

  setExpires: function(numSeconds) {
  },

  updateCookie: function() {
    this.cookies.set(this.opts.cookieName, JSON.stringify(this.content));
  },
  
  // called to create a proxy that monitors the session
  // for new properties being set
  monitor: function() {
    // set up proxies
    var sessionHandler = new Handler(this);

    // all values from content except special values
    sessionHandler.get = function(rcvr, name) {
      if (['clear', 'setExpires'].indexOf(name) > -1)
        return this.target[name];
      else
        return this.target.content[name];
    };

    // set all values to content
    sessionHandler.set = function(rcvr, name, value) {
      this.target.content[name] = value;
      this.target.updateCookie();
    };
    
    var proxySession = Proxy.create(sessionHandler);
    return proxySession;
  }
};


var cookieSession = function(opts) {
  opts.cookieName = opts.cookieName || "session";
  
  return function(req, res, next) {
    var cookies = new Cookies(req, res);
    req.session = new Session(req, res, cookies, opts).monitor();
    next();
  };
};

module.exports = cookieSession;