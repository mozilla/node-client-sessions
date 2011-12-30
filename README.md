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

    var cookieSessions = require("cookie-sessions");
    app.use(cookieSessions({
        cookieName: 'session',
        secret: 'blargadeeblargblarg',
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

    // later, in a request
    req.session.foo = 'bar';
    req.session.baz = 'baz2';

    // results in a Set-Cookie header

    // no updates to session results in no Set-Cookie header

    // and then
    if (req.session.foo == 'bar') {
      // do something
    }

    // have the session expire 24 hours from now
    // this will not refresh automatically with activity
    // you have to call req.session.setExpires again
    req.session.setExpires(24 * 60 * 60 * 1000);

    // clear the session
    req.session.clear();