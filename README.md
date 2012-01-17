Secure sessions stored in cookies, for node.js
Middleware for Connect / Express apps.

Session content is secure and tamper-free.

This does *not* use connect's built-int session middleware, because,
if it did, things would get nasty in implementation given the conflict
between the session ID and the session content itself. Also, this library
uses its own cookie parser so that setup is easier and less error-prone.

I don't recommend using both this middleware and connect's built-in
session middleware.


API
===

    var clientSessions = require("client-sessions");
    app.use(clientSessions({
        cookieName: 'session_state',    // defaults to session_state
        secret: 'blargadeeblargblarg', // MUST be set
        // true session duration:
        // will expire after duration (ms)
        // from last session.reset() or
        // initial cookieing.
        duration: 24 * 60 * 60 * 1000, // defaults to 1 day
      }));

    // later, in a request
    req.session.foo = 'bar';
    req.session.baz = 'baz2';
    // results in a Set-Cookie header

    console.log(req.session.baz)
    // no updates to session results in no Set-Cookie header

    // and then
    if (req.session.foo == 'bar') {
      // do something
    }

    // reset the session, preserving some variables
    // if they exist. This means the session's creation time
    // will be reset to now, with expiration in duration (ms).
    req.session.reset(['csrf']);

Optionally, if you'd like more explicit control over the cookie parameters you can do:


    app.use(clientSessions({
        cookieName: 'session_state',    // defaults to session_state
        secret: 'blargadeeblargblarg', // MUST be set
        // true session duration:
        // will expire after duration (ms)
        // from last session.reset() or
        // initial cookieing.
        duration: 24 * 60 * 60 * 1000, // defaults to 1 day
        cookie: {
          path: '/api',
          // cookie expiration parameters
          // this gets updated on every cookie call,
          // so it's not appropriate for saying that the session
          // expires after 2 weeks, for example, since the cookie
          // may get updated regularly and push the time back.
          maxAge: 14 * 24 * 60 * 60 * 1000 // in ms
          httpOnly: true, // defaults to true
          secure: false   // defaults to false
        }
      }));
