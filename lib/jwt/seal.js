// Load modules.
var jws = require('./jws')
  , jwe = require('./jwe')
  , merge = require('utils-merge')
  , NotValidError = require('../errors/notvaliderror')
  , ALGORITHM_OPTIONS = require('./constants').ALGORITHM_OPTIONS;


var ALG_MAP = {
  'hmac-sha256': 'HS256',
  'rsa-sha256': 'RS256'
}

var ENCRYPTION_ALGORITHMS = [ 'aes128-cbc-hmac-sha256' ];
var SIGNING_ALGORITHMS = [ 'hmac-sha256', 'rsa-sha256' ];


/**
 * Seal a security token in a JWT envelope.
 *
 * JSON Web Token (JWT) is a compact, URL-safe message security format.  JWT is
 * a subset of Javascript Object Signing and Encription (JOSE).  JWT profiles
 * JOSE in a manner that puts the following restrictions in place:
 *
 *   - Only the compact serialization is valid.  The larger JSON serialization
 *     is not allowed.
 *   - The payload must be a JSON data structure.  JOSE allows for other data
 *     encodings, signalled via the `cty` claim in the header.
 *
 * 
 *
 * References:
 *  - [JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
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
  
  
  return function jwt(claims, recipients, options, cb) {
    if (!Array.isArray(recipients)) {
      recipients = [ recipients ];
    }
    if (typeof options == 'function') {
      cb = options;
      options = undefined;
    }
    recipients = recipients || []
    options = options || {};
    
    //var audience = options.audience || [];
    //var audience = options;
    if (recipients.length > 1) {
      return cb(new Error('Unable to seal fernet tokens for multiple recipients'));
    }
    
    var confidential = options.confidential !== undefined ? options.confidential : true;
    //var confidential = false;
    
    
    var query  = {
      recipient: recipients[0] ? recipients[0] : undefined,
      usage: confidential ? 'encrypt' : 'sign',
      // TODO: Implement way to pass in negotiated algorithms?
      //signingAlgorithms: options.signingAlgorithms
      algorithms: confidential ? ENCRYPTION_ALGORITHMS : SIGNING_ALGORITHMS
    }
  
    keying(recipients[0], query, function(err, keys) {
      // TODO: Loop through key to find applicable one.
      var key = keys[0];
      
      key.algorithm = key.algorithm || (confidential ? 'aes128-cbc-hmac-sha256' : (key.secret ? 'hmac-sha256' : 'rsa-sha256'));
      
      var header = { typ: 'JWT' }
        , token;
      
      header.alg = ALG_MAP[key.algorithm];
      if (key.id) { header.kid = key.id; }
      
      if (recipients.length && recipients[0] !== null) {
        var i, len;
        claims.aud = [];
        for (i = 0, len = recipients.length; i < len; ++i) {
          claims.aud.push(recipients[i].identifier);
        }
        if (claims.aud.length == 1) {
          claims.aud = claims.aud[0];
        }
      }
      
      
      function proceed() {
        if (confidential) {
          jwe.encrypt(claims, header, key, function(err, token) {
            if (err) { return cb(err); }
            return cb(null, token);
          });
        } else {
          jws.sign(claims, key, function(err, token) {
            if (err) { return cb(err); }
            return cb(null, token);
          });
        }
      }
      
      
      
      //if (options.bindingCallback) {
      if (0) {
        /*
        options.bindingCallback(key.algorithm, function(err, bindingClaims) {
          if (err) { return cb(err); }
          merge(claims, bindingClaims);
          return proceed();
        })
        */
      } else {
        proceed();
      }
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
