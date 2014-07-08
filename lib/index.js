/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const crypto = require('./crypto');

module.exports = exports = require('./middleware');
exports.util = {
  encode: crypto.encode,
  decode: crypto.decode,
  computeHmac: crypto.computeHmac
};
