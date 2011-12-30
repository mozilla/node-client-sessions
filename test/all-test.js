
var vows = require("vows"),
    assert = require("assert"),
    cookieSessions = require("../index"),
    express = require("express"),
    tobi = require("tobi"),
    Browser = require("zombie");

// set up the session middleware
var middleware = cookieSessions({
  cookieName: 'session',
  secret: 'yo',
  cookie: {
    maxAge: 5000
  }
});

var suite = vows.describe('all');

suite.addBatch({
  "a single request object" : {
    topic: function() {
      var self = this;

      // simple app
      var app = express.createServer();
      app.use(middleware);
      app.get("/foo", function(req, res) {
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
    },
    "set variables and clear them yields no variables": function(err, req) {
      req.session.bar = 'baz';
      req.session.clear();
      assert.isUndefined(req.session.bar);
    }
  }
});

suite.addBatch({
  "a single request object" : {
    topic: function() {
      var self = this;

      // simple app
      var app = express.createServer();
      app.use(middleware);
      app.get("/foo", function(req, res) {
        req.session.foo = 'foobar';
        res.send("hello");
      });

      var browser = tobi.createBrowser(app);
      browser.get("/foo", function(res, $) {
        self.callback(null, res);
      });
    },
    "includes a set-cookie header": function(err, res) {
      assert.isArray(res.headers['set-cookie']);
    },
    "with an expires attribute": function(err, res) {
      assert.match(res.headers['set-cookie'][0], /expires/);      
    },
    "with a path attribute": function(err, res) {
      assert.match(res.headers['set-cookie'][0], /path/);
    }
  }
});

suite.addBatch({
  "across two requests" : {
    topic: function() {
      var self = this;

      // simple app
      var app = express.createServer();
      app.use(middleware);
      app.get("/foo", function(req, res) {
        req.session.clear();
        req.session.foo = 'foobar';
        req.session.bar = [1, 2, 3];
        res.send("foo");
      });

      app.get("/bar", function(req, res) {
        self.callback(null, req);
        res.send("bar");
      });

      var browser = tobi.createBrowser(app);
      browser.get("/foo", function(res, $) {
        browser.get("/bar", function(res, $) {
        });
      });
    },
    "session maintains state": function(err, req) {
      assert.equal(req.session.foo, 'foobar');
      assert.equal(req.session.bar.length, 3);
      assert.equal(req.session.bar[0], 1);
      assert.equal(req.session.bar[1], 2);
      assert.equal(req.session.bar[2], 3);
    }
  }
});

suite.addBatch({
  "across three requests" : {
    topic: function() {
      var self = this;

      // simple app
      var app = express.createServer();
      app.use(middleware);
      app.get("/foo", function(req, res) {
        req.session.clear();
        req.session.foo = 'foobar';
        req.session.bar = 'foobar2';
        res.send("foo");
      });

      app.get("/bar", function(req, res) {
        delete req.session['bar'];
        res.send("bar");
      });

      app.get("/baz", function(req, res) {
        self.callback(null, req);
        res.send("baz");
      });
      
      var browser = tobi.createBrowser(app);
      browser.get("/foo", function(res, $) {
        browser.get("/bar", function(res, $) {
          browser.get("/baz", function(res, $) {
          });
        });
      });
    },
    "session maintains state": function(err, req) {
      assert.equal(req.session.foo, 'foobar');
      assert.isUndefined(req.session.bar);
    }
  }
});

suite.addBatch({
  "reading from a session" : {
    topic: function() {
      var self = this;

      // simple app
      var app = express.createServer();
      app.use(middleware);
      app.get("/foo", function(req, res) {
        req.session.foo = 'foobar';
        res.send("foo");
      });

      app.get("/bar", function(req, res) {
        res.send(req.session.foo);
      });

      var browser = tobi.createBrowser(app);
      browser.get("/foo", function(res, $) {
        browser.get("/bar", function(res, $) {
          // observe the response to the second request
          self.callback(null, res);
        });
      });
    },
    "does not set a cookie": function(err, res) {
      assert.isUndefined(res.headers['set-cookie']);
    }
  }
});

suite.export(module);