// Load modules.
var jws = require('jws');

exports = module.exports = function verify(token, header, payload, key, cb) {
  var ok;
  try {
    // TODO: Pass alg explicitly, don't take header val
    ok = jws.verify(token, header.alg, key);
  } catch(ex) {
    return cb(ex);
  }
  
  if (!ok) {
    return cb(new NotValidError('Token signature invalid'));
  }
  
  var conditions = {};
  // TODO: Put exiresAt on conditions
  
  return cb(null, payload, conditions);
}
