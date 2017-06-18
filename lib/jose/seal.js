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
 * Seal a security token in a JOSE envelope.
 *
 * Javascript Object Signing and Encription (JOSE) is a JSON-based message
 * security format, that povides for integrity protection and/or encryption of
 * (typically, but not limited to) JSON data structures.
 *
 * References:
 *  - [Javascript Object Signing and Encryption](https://datatracker.ietf.org/wg/jose/about/)
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
  
  
  return function jose(claims, options, cb) {
    if (typeof options == 'function') {
      cb = options;
      options = undefined;
    }
    options = options || {};
    
    var audience = options.audience || [];
    
    var confidential = options.confidential !== undefined ? options.confidential : true;
    // TODO: nonRepudiation
    
    var self = this
      , recip
      , keys = []
      , issuer
      , i = 0;
    
    // TODO: The key lookup queryies can be parallelized.
    (function iter(err, data) {
      if (err) { return cb(err); }

      recip = audience[i++];
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
        recipient: recip,
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
