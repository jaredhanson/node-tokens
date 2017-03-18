// Load modules.
var jose = require('node-jose');

exports = module.exports = function encrypt(claims, header, key, cb) {
  console.log('key: ' + key);
  
  var keystore = jose.JWK.createKeyStore();
  console.log(keystore);
  
    keystore.generate("oct", 256).
        then(function(result) {
          // {result} is a jose.JWK.Key
          console.log('GEN OCT');
          console.log(result);
          //key = result;
          
          console.log(keystore.toJSON(true))
          
          console.log('B64 IT ' +  key.secret);
          var x = jose.util.base64url.encode(key.secret)
          console.log(x);
          key.secret = key.secret || '4ZQKhHBQA3KTV-BtPjrQUEpLzYDY4BVv-XCQRLNm23M'
          
          return jose.JWK.asKey({ kty: 'oct',
            kid: '1',
            k: jose.util.base64url.encode(key.secret) });
          
          
          return result;
          
          console.log(keystore.all());
          
        }).
        then(function(key) {
          console.log('ENCRYPT SOMETHIGN!');
          
          jose.JWE.createEncrypt({ format: 'compact' }, key).
            update('Hello World!').
            final().
            then(function(result) {
              // {result} is a String -- JWE using the Compact Serialization
      
              console.log(result)
              
              return cb(null, result);
            });
          
        });
  
  
  
  
  /*
  var token;
  try {
    token = jws.sign({ header: header, payload: claims, secret: key });
  } catch (ex) {
    return cb(ex);
  }
  if (!token) { return cb(new Error('jws.sign failed')); }
  return cb(null, token);
  */
}
