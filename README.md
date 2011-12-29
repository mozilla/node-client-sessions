secure sessions stored in cookies, for node.js

The session content is built to be secure and tamper-free.

API
===

We don't want this library to depend on making any other calls, e.g. cookieParser.

    var cookieSessions = require("cookie-sessions");
    app.use(cookieSessions({
        cookieName: 'session',
        secret: 'blargadeeblargblarg',
        cookie: {
          path: '/api',
          httpOnly: true, // defaults to true
          secure: true    // defaults to true
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