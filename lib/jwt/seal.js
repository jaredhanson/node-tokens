// Load modules.
var jws = require('./jws')
  , jwe = require('./jwe')
  , NotValidError = require('../errors/notvaliderror');


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
 *     encodings, signalled via the `typ` claim in the header.
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
  
  
  return function sat(claims, options, cb) {
    if (typeof options == 'function') {
      cb = options;
      options = undefined;
    }
    options = options || {};
    
    
    //var confidential = options.confidential !== undefined ? options.confidential : false;
    var confidential = options.confidential !== undefined ? options.confidential : true;
    
    var query  = {
      recipients: options.audience,
      usage: confidential ? 'encrypt' : 'sign',
      // TODO: Implement way to pass in negotiated algorithms?
      //signingAlgorithms: options.signingAlgorithms
      algorithms: confidential ? ENCRYPTION_ALGORITHMS : SIGNING_ALGORITHMS
    }
    
    keying(query, function(err, keys) {
      // TODO: Loop through key to find applicable one.
      var key = keys[0];
      
      var header = { typ: 'JWT' }
        , token;
      
      header.alg = ALG_MAP[key.algorithm];
      if (key.id) { header.kid = key.id; }
      
      if (confidential) {
        jwe.encrypt(claims, header, key, function(err, token) {
          if (err) { return cb(err); }
          return cb(null, token);
        });
      } else {
        jws.sign(claims, header, key.secret || key.privateKey, function(err, token) {
          if (err) { return cb(err); }
          return cb(null, token);
        });
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
