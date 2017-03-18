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
  
  /*
  var keystore = jose.JWK.createKeyStore();
  var props = {
    kid: 'gBdaS-G8RLax2qgObTD94w',
    alg: 'A256GCM',
    use: 'enc'
  };
  //keystore.generate("oct", 256, props).
  keystore.generate("RSA", 256).
          then(function(key) {
            // {result} is a jose.JWK.Key
            //key = result;
            
            console.log(keystore.toJSON(true));
            console.log(key.toJSON(true));
            
          });
  
  return;
  */
  
  var jwk = toKey(key);
  
  //console.log(key);
  //return;
  
  Promise.all([ jwk ]).
    then(function(keys) {
      var payload = JSON.stringify(claims);
      
      return jose.JWE.createEncrypt({ format: 'compact', fields: { typ: 'JWT' } }, keys).
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
