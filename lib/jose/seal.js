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
  
  
  return function jose_seal(claims, options, cb) {
    if (typeof options == 'function') {
      cb = options;
      options = undefined;
    }
    options = options || {};
    
    var confidential = options.confidential !== undefined ? options.confidential : true;
    // TODO: nonRepudiation
    
    var self = this
      , recips = options.audience
      , recip
      , keys = []
      , issuer
      , i = 0;
    
    // TODO: The key lookup queryies can be parallelized.
    (function iter(err, data) {
      if (err) { return cb(err); }

      recip = recips[i++];
      if (!recip) {
        if (confidential) {
          jwe.encrypt(claims, undefined, keys, function(err, token) {
            if (err) { return cb(err); }
            return cb(null, token);
          });
        } else {
          jws.sign(claims, keys, issuer, function(err, token) {
            if (err) { return cb(err); }
            return cb(null, token);
          });
        }
        return;
      }
      
      var query  = {
        // FIXME: Only query for one recipient
        recipients: [ recip ],
        usage: confidential ? 'encrypt' : 'sign',
        algorithms: confidential ? ENCRYPTION_ALGORITHMS : SIGNING_ALGORITHMS
      }
      
      keying(query, function(err, key, iss) {
        if (err) { return iter(err); }
        keys.push(key[0]);
        issuer = issuer || iss;
        iter();
      });
    })();
  }
}
