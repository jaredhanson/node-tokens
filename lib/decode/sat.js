var moment = require('moment')
  , jws = require('jws');


module.exports = function(options, keying) {
  if (typeof options == 'function') {
    keying = options;
    options = undefined;
  }
  options = options || {};
  
  if (!keying) { throw new TypeError('SAT decoding requires a keying callback'); }
  
  return function sat(data, cb) {
    var token = jws.decode(data, { json: true });
    if (!token) { return cb(); }
    
    var header = token.header
      , payload = token.payload;
    
    
    function keyed(err, key) {
      if (err) { return cb(err); }
      var ok = jws.verify(data, key);
      if (!ok) {
        return cb(new Error('Invalid signature on structured access token'));
      }
      
      // TODO: Check dates
      
      var claims = {};
      claims.issuer = payload.iss;
      claims.audience = payload.aud;
      claims.expiresAt = moment.unix(payload.exp).toDate();
      
      return cb(null, claims);
    }
    
    try {
      var arity = keying.length;
      if (arity == 3) {
        keying(payload.iss, header, keyed);
      } else { // arity == 2
        keying(payload.iss, keyed);
      }
    } catch (ex) {
      return cb(ex);
    }
    
  }
}
