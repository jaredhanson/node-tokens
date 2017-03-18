// Load modules.
var jws = require('jws');

exports = module.exports = function verify(token, header, payload, key, cb) {
  var ok;
  try {
    ok = jws.verify(token, header.alg, key);
  } catch(ex) {
    return cb(ex);
  }
  
  if (!ok) {
    return cb(new NotValidError('Token signature invalid'));
  }
  
  var tok = {
    //issuer: query.sender,
    headers: {
      issuer: payload.iss
    },
    claims: payload
  }
  
  return cb(null, tok);
}
