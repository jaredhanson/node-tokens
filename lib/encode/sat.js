var jws = require('jws')
  , NotValidError = require('../errors/notvaliderror');



/**
 * References:
 *  - [Structured Access Token for Sharing Authorization Grant between a Resource Server and an Authorization Server](http://tools.ietf.org/html/draft-sakimura-oidc-structured-token-01)
 *  - [JSON Web Token (JWT)](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-14)
 */
module.exports = function(options) {
  options = options || {};

  var issuer = options.issuer
    , key = options.key
    , kid = options.kid
    , algorithm = options.algorithm || 'RS256';
  
  if (!issuer) { throw new TypeError('SAT encoding requires an issuer'); }
  if (!key) { throw new TypeError('SAT encoding requires an key'); }
  
  
  return function sat(info, cb) {
    if (!info.subject) { return cb(new NotValidError('Structured access token requires a subject claim')); }
    if (!info.audience) { return cb(new NotValidError('Structured access token requires an audience claim')); }
    
    var claims = {}
      , header, token, val;
    claims.jti = info.id;
    claims.iss = issuer;
    claims.sub = info.subject;
    claims.aud = info.audience;
    claims.azp = info.authorizedPresenter;
    claims.iat = Math.floor(Date.now() / 1000);
    
    // see note in ../decode/sat.js about use of scope
    if(Array.isArray(info.scope)) { info.scope = info.scope.join(' '); }
    if(typeof info.scope == 'string') { claims.scope = info.scope; }

    val = info.expiresAt;
    if (val instanceof Date) {
      claims.exp = Math.floor(val.getTime() / 1000);
    } else {
      return cb(new NotValidError('Structured access token requires an expiration time claim'));
    }
    val = info.notBefore;
    if (val instanceof Date) {
      claims.exp = Math.floor(val.getTime() / 1000);
    }
    
    if (typeof key == 'function') {
      key(function(err, key, kid) {
        if (err) { return cb(er); }
        
        var header = { typ: 'JWT', alg: algorithm, kid: kid }
          , token;
        try {
          token = jws.sign({ header: header, payload: claims, secret: key });
        } catch (ex) {
          return cb(ex);
        }
        if (!token) { return cb(new Error('jws.sign failed')); }
        cb(null, token);
      });
    } else {
      header = { typ: 'JWT', alg: algorithm, kid: kid };
      try {
        token = jws.sign({ header: header, payload: claims, secret: key });
      } catch (ex) {
        return cb(ex);
      }
      if (!token) { return cb(new Error('jws.sign failed')); }
      cb(null, token);
    }
  }
}
