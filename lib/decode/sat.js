var moment = require('moment')
  , jws = require('jws')
  , NotValidError = require('../errors/notvaliderror');


module.exports = function(options, keying) {
  if (typeof options == 'function') {
    keying = options;
    options = undefined;
  }
  options = options || {};
  
  if (!keying) { throw new TypeError('SAT decoding requires a keying callback'); }
  
  var audience = options.audience;
  if (!Array.isArray(audience)) {
    audience = [ audience ];
  }
  
  return function sat(data, cb) {
    // Decode the JWT so the header and payload are available, as they contain
    // fields needed to find the corresponding key.  Note that at this point, the
    // assertion has not actually been verified.  It will be verified later, after
    // the keying material has been retrieved.
    var token = jws.decode(data, { json: true });
    if (!token) { return cb(); }
    
    var header = token.header
      , payload = token.payload;
    
    // Validate the assertion.
    // https://tools.ietf.org/html/draft-sakimura-oidc-structured-token-01#section-3
    // https://tools.ietf.org/html/draft-sakimura-oidc-structured-token-01#section-4
    // http://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-07#section-3
    if (!payload.iss) { return cb(new NotValidError('Token missing required claim: iss')); }
    if (!payload.sub) { return cb(new NotValidError('Token missing required claim: sub')); }
    if (!payload.aud) { return cb(new NotValidError('Token missing required claim: aud')); }
    if (!payload.exp) { return cb(new NotValidError('Token missing required claim: exp')); }
    
    // TODO: Handle aud claim that is an array.
    if (audience.indexOf(payload.aud) == -1) {
      return cb(new NotValidError('Token not intended for this audience'));
    }
    
    var now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) { // expired
      return cb(new NotValidError('Token expired'));
    }
    if (payload.nbf && payload.nbf > now) { // not yet acceptable
      return cb(new NotValidError('Token not yet acceptable'));
    }
    
    
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
  };
};
