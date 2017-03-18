// Load modules.
var jose = require('node-jose');

function toKey(key) {
  return jose.JWK.asKey({
    kty: 'oct',
    kid: key.id,
    k: jose.util.base64url.encode(key.secret)
  });
}


exports = module.exports = function encrypt(claims, header, key, cb) {
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
    });
}
