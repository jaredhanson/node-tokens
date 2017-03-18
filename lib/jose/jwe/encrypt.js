// Load modules.
var jose = require('node-jose');

function toKey(key) {
  // kty: RSA
  if (key.publicKey) {
    
    // Use the PEM parsing functionality of `jose` to construct a key.
    return jose.JWK.asKey(key.publicKey, 'pem')
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
      k: jose.util.base64url.encode(key.secret),
      //alg: 'A128CBC-HS256',
      //use: 'enc'
      //alg: 'A128KW',
      //alg: ['A128CBC-HS256', 'A256KW']
      //alg: 'A128CBC-HS256' // not default
      //alg: 'A256GCM',
    },
    reference: key.id !== undefined ? true : false,
    //header: { alg: 'A256KW' }
  }
}


exports = module.exports = function encrypt(claims, header, key, cb) {
  
  var jwk = toKey(key);
  
  var encoding = 'json';
  
  Promise.all([ jwk ]).
    then(function(keys) {
      var type = 'json';
      var payload = JSON.stringify(claims);
      
      return jose.JWE.createEncrypt({ format: 'json', fields: { typ: 'JOSE+JSON', cty: 'json' } }, keys).
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
