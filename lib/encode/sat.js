var jws = require('jws');


/**
 * References:
 *  - [Structured Access Token for Sharing Authorization Grant between a Resource Server and an Authorization Server](http://tools.ietf.org/html/draft-sakimura-oidc-structured-token-01)
 *  - [JSON Web Token (JWT)](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-14)
 */
module.exports = function(options) {
  options = options || {};

  var issuer = options.issuer
    , key = options.key
    , algorithm = options.algorithm || 'rs256';
  
  
  return function sat(info) {
    
    var claims = {};
    claims.jti = info.id;
    claims.iss = issuer;
    claims.sub = info.subject;
    claims.aud = info.audience;
    claims.azp = info.presenter;
    claims.iat = Math.floor(Date.now() / 1000);
    
    var header = { typ: 'JWT', alg: algorithm };
    
    var token = jws.sign({ header: header, payload: claims, secret: key });
    return token;
  }
}
