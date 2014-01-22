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
    , algorithm = options.algorithm || 'RS256';
  
  
  return function sat(info) {
    if (!info.subject) { throw new Error('Structured access token requires a subject claim'); }
    if (!info.audience) { throw new Error('Structured access token requires an audience claim'); }
    
    var claims = {}, val;
    claims.jti = info.id;
    claims.iss = issuer;
    claims.sub = info.subject;
    claims.aud = info.audience;
    claims.azp = info.authorizedPresenter;
    claims.iat = Math.floor(Date.now() / 1000);

    val = info.expiresAt;
    if (val instanceof Date) {
      claims.exp = Math.floor(val.getTime() / 1000);
    } else {
      throw new Error('Structured access token requires an expiration time claim');
    }
    val = info.notBefore;
    if (val instanceof Date) {
      claims.exp = Math.floor(val.getTime() / 1000);
    }
    
    var header = { typ: 'JWT', alg: algorithm };
    var token = jws.sign({ header: header, payload: claims, secret: key });
    return token;
  }
}
