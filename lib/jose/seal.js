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
  if (typeof options == 'string') {
    options = { issuer: options };
  }
  if (typeof options == 'function') {
    keying = options;
    options = undefined;
  }
  options = options || {};

  var issuer = options.issuer;
  
  
  return function jose(claims, options, cb) {
    if (typeof options == 'function') {
      cb = options;
      options = undefined;
    }
    options = options || {};
    
    // The recipients list is defaulted to an empty array.  This indicates that
    // the intended recipient of the object is the same entity that is issuing
    // the object.
    var recipients = options.recipients || [ null ];
    
    var confidential = options.confidential !== undefined ? options.confidential : true;
    // TODO: nonRepudiation
    
    var self = this
      , recipient
      , keys = []
      , issuer
      , i = 0;
    
    // TODO: The key lookup queryies can be parallelized.
    (function iter(err, data) {
      if (err) { return cb(err); }

      recipient = recipients[i++];
      if (recipient === undefined) { // done
        // The strict undefined condition is necessitated by the above single
        // element array containing a `null` value.  In this case, a single
        // iteration is desired to query for the issuing entity's keys.
        
        if (confidential) {
          jwe.encrypt(claims, undefined, keys, function(err, object) {
            if (err) { return cb(err); }
            return cb(null, object);
          });
        } else {
          jws.sign(claims, keys, issuer, function(err, object) {
            if (err) { return cb(err); }
            return cb(null, object);
          });
        }
        return;
      }
      
      var query  = {
        usage: confidential ? 'encrypt' : 'sign',
        algorithms: confidential ? ENCRYPTION_ALGORITHMS : SIGNING_ALGORITHMS
      };
      keying(recipient || undefined, query, function(err, key, entity) {
        if (err) { return iter(err); }
        keys.push(key);
        issuer = issuer || entity;
        iter();
      });
    })();
  }
}
