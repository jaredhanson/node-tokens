/**
 * Module dependencies.
 */
var moment = require('moment')
  , jws = require('jws')
  , NotValidError = require('../errors/notvaliderror');


/**
 * Decode a structured access token.
 *
 * References:
 *  - [Structured Access Token for Sharing Authorization Grant between a Resource Server and an Authorization Server](http://tools.ietf.org/html/draft-sakimura-oidc-structured-token-01)
 *  - [JSON Web Token (JWT)](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-14)
 */
module.exports = function(options, keying) {
  if (typeof options == 'function') {
    keying = options;
    options = undefined;
  }
  options = options || {};
  
  if (!keying) { throw new TypeError('SAT decoding requires a keying callback'); }
  
  var audience = options.audience || [];
  if (!Array.isArray(audience)) {
    audience = [ audience ];
  }
  
  return function sat(data, cb) {
    var aliases = audience;
    
    
    // Decode the JWT so the header and payload are available, as they contain
    // fields needed to find the corresponding key.  Note that at this point, the
    // assertion has not actually been verified.  It will be verified later, after
    // the keying material has been retrieved.
    var token = jws.decode(data, { json: true });
    if (!token) { return cb(); }
    
    var header = token.header
      , payload = token.payload;
    
    // Validate the assertion.
    // https://tools.ietf.org/html/draft-sakimura-oidc-structured-token-01#section-3
    // https://tools.ietf.org/html/draft-sakimura-oidc-structured-token-01#section-4
    // http://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-07#section-3
    if (!payload.iss) { return cb(new NotValidError('Token missing required claim: iss')); }
    if (!payload.sub) { return cb(new NotValidError('Token missing required claim: sub')); }
    if (!payload.aud) { return cb(new NotValidError('Token missing required claim: aud')); }
    if (!payload.exp) { return cb(new NotValidError('Token missing required claim: exp')); }
    
    var aud = payload.aud;
    if (!Array.isArray(aud)) {
      aud = [ aud ];
    }
    // TODO: Audience checking should be push to authorization, if no audience list is
    //       passed.  If passed, it is an optimization to avoid PKI calls
    var aok = aliases.some(function(a) { return aud.indexOf(a) != -1 });
    if (!aok) {
      return cb(new NotValidError('Token audience of '+payload.aud+' not found in '+aliases));
    }
    
    
    var now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) { // expired
      return cb(new NotValidError('Token expired'));
    }
    if (payload.nbf && payload.nbf > now) { // not yet acceptable
      return cb(new NotValidError('Token not yet acceptable'));
    }
    
    
    function keyed(err, key) {
      if (err) { return cb(err); }
      var ok = jws.verify(data, header.alg, key);
      if (!ok) {
        return cb(new NotValidError('Token signature invalid'));
      }
      
      var claims = {};
      claims.issuer = payload.iss;
      claims.subject = payload.sub;
      claims.audience = aud;
      claims.expiresAt = moment.unix(payload.exp).toDate();
      if (payload.azp) { claims.authorizedPresenter = payload.azp; }
      if (payload.scope) {
        // NOTE: "scope" is not defined as a claim by the SAT specification.
        //       However, it is widely needed when making authorization
        //       decisions, and is parsed here as a convienience.  The parsing
        //       is in accordance with established industry conventions, as set
        //       by Google, IETF drafts, and others.
        //
        // References:
        //   - https://developers.google.com/accounts/docs/OAuth2ServiceAccount
        //   - http://tools.ietf.org/html/draft-richer-oauth-introspection-04
        
        claims.scope = payload.scope.split(' ');
      }
      
      return cb(null, claims);
    }
    
    try {
      var arity = keying.length;
      if (arity == 4) {
        keying(payload.iss, payload.aud, header, keyed);
      } else if (arity == 3) {
        keying(payload.iss, header, keyed);
      } else { // arity == 2
        keying(payload.iss, keyed);
      }
    } catch (ex) {
      return cb(ex);
    }
  };
};
