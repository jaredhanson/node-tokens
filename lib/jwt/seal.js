// Load modules.
var jws = require('jws')
  , NotValidError = require('../errors/notvaliderror');


var ALG_MAP = {
  'hmac-sha256': 'HS256',
  'rsa-sha256': 'RS256'
}


/**
 * Encode a security token as a JWT.
 *
 * References:
 *  - [Structured Access Token for Sharing Authorization Grant between a Resource Server and an Authorization Server](http://tools.ietf.org/html/draft-sakimura-oidc-structured-token-01)
 *  - [JSON Web Token (JWT)](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-14)
 */
module.exports = function(options, keying) {
  if (typeof options == 'function') {
    keying = options;
    options = undefined;
  }
  options = options || {};

  var issuer = options.issuer
    , key = options.key
    , kid = options.kid
    , algorithm = options.algorithm || 'RS256';
  
  //if (!issuer) { throw new TypeError('SAT encoding requires an issuer'); }
  
  
  return function sat(claims, options, cb) {
    if (typeof options == 'function') {
      cb = options;
      options = undefined;
    }
    options = options || {};
    
    var query  = {
      recipients: options.audience,
      usage: 'sign',
      // TODO: Implement way to pass in negotiated algorithms?
      //signingAlgorithms: options.signingAlgorithms
      algorithms: [ 'hmac-sha256', 'rsa-sha256' ]
    }
    
    keying(query, function(err, keys) {
      // TODO: Loop through key to find applicable one.
      var key = keys[0];
      
      var header = { typ: 'JWT' }
        , token;
      
      header.alg = ALG_MAP[key.algorithm];
      if (key.id) { header.kid = key.id; }
        
      try {
        token = jws.sign({ header: header, payload: claims, secret: key.secret || key.privateKey });
      } catch (ex) {
        return cb(ex);
      }
      if (!token) { return cb(new Error('jws.sign failed')); }
      
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
