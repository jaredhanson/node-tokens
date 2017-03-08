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
    , key = options.key
    , kid = options.kid
    , algorithm = options.algorithm || 'RS256';
  
  if (!issuer) { throw new TypeError('SAT encoding requires an issuer'); }
  
  
  return function sat(claims, options, cb) {
    console.log('SEAL A JWT!!!!!');
    console.log(claims);
    console.log(options);
    
    var query  = {
      recipients: options.audience,
      usage: 'sign',
      signingAlgorithms: options.signingAlgorithms
    }
    
    keying(query, function(err, keys) {
      // TODO: Loop through key to find applicable one.
      var key = keys[0];
      
      // TODO: Convert key alg to JWA
      var header = { typ: 'JWT', alg: 'RS256', kid: key.id }
        , token;
        
      // FIXME: Remove this hack
      if (!key.id) {
        header.alg = 'HS256'
      }
      
      claims.iss = claims.iss || issuer;
        
      try {
        token = jws.sign({ header: header, payload: claims, secret: key.privateKey || key.secret });
      } catch (ex) {
        return cb(ex);
      }
      if (!token) { return cb(new Error('jws.sign failed')); }
      console.log('SIGNED TOKEN!');
      console.log(token);
      
      cb(null, token);
    });
    
    
    return;
    // FIXME: Clean up below here.
    
    
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
      key(function(err, key, kid) {
        if (err) { return cb(er); }
        
        var header = { typ: 'JWT', alg: algorithm, kid: kid }
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
