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
  }
}
