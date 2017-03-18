// Load modules.
var jose = require('node-jose');

exports = module.exports = function encrypt(claims, header, key, cb) {
  var jwk = jose.JWK.asKey({
    kty: 'oct',
    kid: '1',
    k: jose.util.base64url.encode(key.secret)
  });
  
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
