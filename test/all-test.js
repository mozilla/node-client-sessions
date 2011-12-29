
var vows = require("vows"),
    assert = require("assert"),
    cookieSessions = require("../index"),
    express = require("express"),
    tobi = require("tobi"),
    Browser = require("zombie");

// set up the session middleware
var middleware = cookieSessions({
  cookieName: 'session',
  secret: 'yo'
});

var suite = vows.describe('all');

suite.addBatch({
  "request object" : {
    topic: function() {
      var self = this;

      // simple app
      var app = express.createServer();
      app.use(middleware);
      app.get("/foo", function(req, res) {
        console.log("yay");
        self.callback(null, req);
        res.send("hello");
      });

      var browser = tobi.createBrowser(app);
      browser.get("/foo", function(res, $) {});
    },
    "includes a session object": function(err, req) {
      assert.isObject(req.session);
    },
    "session object has clear method": function(err, req) {
      assert.isFunction(req.session.clear);
    },
    "session object has setExpires method": function(err, req) {
      assert.isFunction(req.session.setExpires);
    },
    "session object stores and retrieves values properly": function(err, req) {
      req.session.foo = 'bar';
      assert.equal(req.session.foo, 'bar');
    }
  }
});

suite.export(module);