// Load modules.
var jws = require('jws')
  , NotValidError = require('../errors/notvaliderror');



/**
 * Encode a security token as a JWT.
 *
 * References:
 *  - [Structured Access Token for Sharing Authorization Grant between a Resource Server and an Authorization Server](http://tools.ietf.org/html/draft-sakimura-oidc-structured-token-01)
 *  - [JSON Web Token (JWT)](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-14)
 */
module.exports = function(options, keying) {
  options = options || {};

  var issuer = options.issuer
    , key = keying || options.key
    , kid = options.kid
    , algorithm = options.algorithm || 'RS256';
  
  if (!issuer) { throw new TypeError('SAT encoding requires an issuer'); }
  if (!key) { throw new TypeError('SAT encoding requires a key or a keying callback'); }
  
  
  return function sat(claims, options, cb) {
    if (typeof options === 'function') {
      cb = options;
      options = undefined;
    }
    options = options || {};

    var payload = {}
      , header, token, val;
    
    payload.jti = claims.id;
    payload.iss = issuer;
    payload.sub = claims.subject;
    payload.aud = claims.audience;
    payload.azp = claims.authorizedPresenter;
    payload.iat = Math.floor(Date.now() / 1000);
    
    // see note in ../decode/sat.js about use of scope
    payload.scope = Array.isArray(claims.scope) ? claims.scope.join(' ') : claims.scope;

    val = claims.expiresAt;
    if (val instanceof Date) {
      payload.exp = Math.floor(val.getTime() / 1000);
    }
    val = claims.notBefore;
    if (val instanceof Date) {
      payload.nbf = Math.floor(val.getTime() / 1000);
    }
    
    if (typeof key == 'function') {
      options.usage = 'sign';
      key(options, function(err, key, info) {
        console.log('JWT KEY KEYED TO');
        console.log(key);
        console.log(info);
        
        if (err) { return cb(er); }
        
        // FIXME:
        algorithm = 'RS256';
        
        var header = { typ: 'JWT', alg: algorithm, kid: info.id }
          , token;
        try {
          token = jws.sign({ header: header, payload: payload, secret: key });
        } catch (ex) {
          return cb(ex);
        }
        if (!token) { return cb(new Error('jws.sign failed')); }
        cb(null, token);
      });
    } else {
      header = { typ: 'JWT', alg: algorithm, kid: kid };
      try {
        token = jws.sign({ header: header, payload: payload, secret: key });
      } catch (ex) {
        return cb(ex);
      }
      if (!token) { return cb(new Error('Failed to sign JWT')); }
      cb(null, token);
    }
  }
}
