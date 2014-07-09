/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const middleware = require('./middleware');
const config = middleware.config;
const session = middleware.session;

module.exports = function clientFactoryGenerator(opts) {

  config(opts);

  return function* clientSession(next) {
    var rawSession = session(this, this.request.req, this.response.res, opts);
    yield next;
    rawSession.updateCookie();
  };
};
