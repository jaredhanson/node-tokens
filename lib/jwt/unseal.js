/**
 * Module dependencies.
 */
var moment = require('moment')
  , jose = require('node-jose')
  , jws = require('jws')
  , _jws = require('./jws')
  , NotValidError = require('../errors/notvaliderror');

// TODO: Add support for `crit` header.  Redefined by JWT from JWS/JWE

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
  
  var aliases = options.aliases || options.audience;
  if (typeof aliases == 'string') {
    aliases = [ aliases ];
  }
  
  return function jwt(token, parameters, cb) {
    if (typeof parameters == 'function') {
      cb = parameters;
      parameters = undefined;
    }
    parameters = parameters || {};
    
    
    var parsed, decoded
      , iss;
      
      
    // Decode the JWT so the header and payload are available, as they contain
    // fields needed to find the corresponding key.  Note that at this point, the
    // assertion has not actually been verified.  It will be verified later, after
    // the keying material has been retrieved.
    try {
      parsed = jose.parse(token)
    } catch(ex) {
      // not a JWT, attempt other parsing
      return cb(null);
    }
    
    iss = parsed.header.iss;
    
    if (parsed.type == 'JWS') {
      decoded = jws.decode(token, { json: true });
      iss = decoded.payload.iss || iss;
    }
    
    
    var query  = {
      id: parsed.header.kid,
      usage: 'verify',
      algorithms: [ 'hmac-sha256' ]
    }
    
    console.log('JWT UNSEAL');
    console.log(query)
    
    keying(parameters.issuer, query, function(err, keys) {
      console.log('GOT KEYS');
      console.log(err);
      console.log(keys);
    
      var key = keys;
      
      if (parsed.type == 'JWS') {
        _jws.verify(token, decoded.header, decoded.payload, key.secret || key.privateKey, function(err, tkn, conditions) {
          if (err) { return cb(err); }
          
          //tkn.issuer = query.sender;
          return cb(null, tkn, conditions);
        });
      } else { // JWE
        // TODO
      }
    
    });
    
    return;
    // FIXME: Clean up below here.
    
    //if (header.alg == 'none') { return cb(new NotValidError('Token unsecured')); }
    
    // Validate the assertion.
    // https://tools.ietf.org/html/draft-sakimura-oidc-structured-token-01#section-3
    // https://tools.ietf.org/html/draft-sakimura-oidc-structured-token-01#section-4
    // http://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-07#section-3
    //if (!payload.iss) { return cb(new NotValidError('Token missing required claim: iss')); }
    //if (!payload.sub) { return cb(new NotValidError('Token missing required claim: sub')); }
    //if (!payload.aud) { return cb(new NotValidError('Token missing required claim: aud')); }
    //if (!payload.exp) { return cb(new NotValidError('Token missing required claim: exp')); }
    
    /*
    var aud = payload.aud;
    if (!Array.isArray(aud)) {
      aud = [ aud ];
    }
    */
    
    // Audience checking is optionally performed here, if and only if a list of
    // acceptable values was passed as an option when creating the decoder
    // function.  This is primarily an optimization to avoid crytographic
    // operations, when the list of valid values are known ahead of time.
    //
    // If acceptable values are not passed as an option, it is assumed that the
    // valid audience is computed based on higher-level protocol information
    // (for example, based on a HTTP request).  In such instances, it is
    // expected that audience checking will be perfored at that level.  Failure
    // to do so is a security violation.
    /*
    if (aliases) {
      var aok = aliases.some(function(a) { return aud.indexOf(a) != -1 });
      if (!aok) {
        return cb(new NotValidError('Token not intended for recipient'));
      }
    }
    
    var now = Math.floor(Date.now() / 1000);
    if (payload.exp <= now) { // expired
      return cb(new NotValidError('Token expired'));
    }
    if (payload.nbf && payload.nbf > now) { // not yet acceptable
      return cb(new NotValidError('Token not yet acceptable'));
    }
    */
    
    //function keyed(err, keys) {
      /*
      var ok;
      try {
        ok = jws.verify(data, header.alg, keys[0].secret);
      } catch(ex) {
        return cb(ex);
      }
      
      if (!ok) {
        return cb(new NotValidError('Token signature invalid'));
      }
      */
      
      // TODO: Check expiration and all of that stuff.
      
      /*
      var claims = {};
      claims.issuer = payload.iss;
      claims.subject = payload.sub;
      claims.audience = aud;
      claims.expiresAt = moment.unix(payload.exp).toDate();
      if (payload.nbf) {
        claims.notBefore = moment.unix(payload.nbf).toDate();
      }
      if (payload.iat) {
        claims.issuedAt = moment.unix(payload.iat).toDate();
      }
      if (payload.azp) {
        claims.authorizedParty =
        claims.authorizedPresenter = payload.azp;
      }
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
        
        if (typeof payload.scope == 'string') {
          claims.scope = payload.scope.split(' ');
        } else if (Array.isArray(payload.scope)) {
          claims.scope = payload.scope;
        } else {
          return cb(new NotValidError('scope claim in JWT must be a string'));
        }
      }
      if (payload.claims) {
        claims.claims = payload.claims;
      }
      if (payload.jti) {
        claims.id = payload.jti;
      }
      
      return cb(null, claims);
      */
    //}
  };
};
