// Load modules.
var jws = require('jws')
  , ALGORITHM_OPTIONS = require('../constants').ALGORITHM_OPTIONS;


exports = module.exports = function sign(claims, key, cb) {
  var opts = ALGORITHM_OPTIONS[key.algorithm];
  if (!opts) {
    return cb(new Error('Unsupported algorithm: ' + key.algorithm));
  }
  
  var header = { typ: 'JWT' };
  header.alg = opts.alg;
  if (key.id) { header.kid = key.id; }

  var token;
  try {
    token = jws.sign({ header: header, payload: claims, secret: key.secret || key.key });
  } catch (ex) {
    return cb(ex);
  }
  if (!token) { return cb(new Error('jws.sign failed')); }
  return cb(null, token);
}
