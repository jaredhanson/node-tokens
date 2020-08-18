// Load modules.
var jose = require('node-jose');

// https://github.com/panva/jose

function toJWK(key) {
  // kty: RSA
  if (key.key) {
    
    // Use the PEM parsing functionality of `jose` to construct a key.
    return jose.JWK.asKey(key.key, 'pem')
      .then(function(k) {
        // Export the parsed key, and override the auto-assigned key
        // ID with the actual key ID.
        var jwk = k.toJSON(true);
        jwk.kid = key.id;
        
        return {
          key: jwk,
          reference: key.id !== undefined ? true : false,
        };
      });
  }
  
  return {
    key: {
      kty: 'oct',
      kid: key.id,
      k: jose.util.base64url.encode(key.secret)
    },
    reference: key.id !== undefined ? true : false
  }
}


exports = module.exports = function sign(claims, keys, issuer, cb) {
  var encoding = 'json';
  if (keys.length == 1) {
    // When the content only needs to be secured with a single digital signature
    // or MAC, use the flattened sytax as an optimization of the fully general
    // JWS JSON Serialization syntax.
    //
    // For more information, refer to:
    //     https://tools.ietf.org/html/rfc7515#section-7.2.2
    encoding = 'flattened';
  }
  
  var jwks = keys.map(toJWK);
  
  Promise.all(jwks).
    then(function(keys) {
      if (issuer && !claims.iss) {
        claims.iss = issuer;
      }
      
      var payload = JSON.stringify(claims);

      // TODO: json format when multiple-signatures

      return jose.JWS.createSign({ format: encoding, fields: { typ: 'JOSE+JSON', cty: 'json' } }, keys).
        update(payload).
        final();
    }).
    then(function(token) {
      return cb(null, token);
    }).
    catch(function(err) {
       // rejection
      
      console.log('ERROR!');
      console.log(err);
    });
}
