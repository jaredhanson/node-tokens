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
    
    // The audienced is defaulted to a single-element array with a `null` value.
    // This indicates that the audience of the token is the same entity issuing
    // the token.
    var audience = options.recipients || [ null ];
    
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
      if (recip === undefined) { // done
        // The strict undefined condition is necessitated by the above single
        // element array containing a `null` value.  In this case, a single
        // iteration is desired to query for the issuing entity's keys.
        
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
        //recipient: recip || undefined,
        usage: confidential ? 'encrypt' : 'sign',
        algorithms: confidential ? ENCRYPTION_ALGORITHMS : SIGNING_ALGORITHMS
      }
      
      console.log('QUERY FOR KEY');
      console.log(recip);
      console.log(query);
      
      keying(recip || undefined, query, function(err, key, iss) {
        if (err) { return iter(err); }
        //keys.push(key[0]);
        keys.push(key);
        issuer = issuer || iss;
        iter();
      });
    })();
  }
}
