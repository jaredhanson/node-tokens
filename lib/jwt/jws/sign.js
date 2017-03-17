// Load modules.
var jws = require('jws');

exports = module.exports = function sign(claims, header, key, cb) {
  var token;
  try {
    token = jws.sign({ header: header, payload: claims, secret: key });
  } catch (ex) {
    return cb(ex);
  }
  if (!token) { return cb(new Error('jws.sign failed')); }
  return cb(null, token);
}
