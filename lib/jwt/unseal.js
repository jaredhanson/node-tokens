/**
 * Module dependencies.
 */
var moment = require('moment')
  , jose = require('node-jose')
  , jws = require('jws')
  , _jws = require('./jws')
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
  
  var aliases = options.aliases || options.audience;
  if (typeof aliases == 'string') {
    aliases = [ aliases ];
  }
  
  return function sat(t, opts, cb) {
    var pt
      , dt, iss;
      
    try {
      pt = jose.parse(t)
    } catch(ex) {
      // not a JWT, attempt other parsing
      return cb(null);
    }
    console.log(pt);
    
    iss = pt.header.iss;
    
    if (pt.type == 'JWS') {
      dt = jws.decode(t, { json: true });
      iss = dt.payload.iss || iss;
    }
    
    
    var query  = {
      sender: iss,
      id: pt.header.kid,
      usage: 'verify',
      algorithms: [ 'hmac-sha256' ]
    }
    
    keying(query, function(err, keys) {
      console.log('GOT KEYS');
      console.log(err);
      console.log(keys);
    
      var key = keys[0];
      
      if (pt.type == 'JWS') {
        _jws.verify(t, dt.header, dt.payload, key.secret || key.privateKey, function(err, tkn) {
          if (err) { return cb(err); }
          
          tkn.issuer = query.sender;
          return cb(null, tkn);
        });
      } else { // JWE
        // TODO
      }
    
    });
    
    return;
    // FIXME: Clean up below here.
    
    // Decode the JWT so the header and payload are available, as they contain
    // fields needed to find the corresponding key.  Note that at this point, the
    // assertion has not actually been verified.  It will be verified later, after
    // the keying material has been retrieved.
    var token = jws.decode(data, { json: true });
    if (!token) {
      // The token could not be decoded as a JWT.  Return without claims under
      // the assumption that the token is encoded in a different format.  It is
      // expected that other decoders will attempt to decode the token.
      return cb();
    }
    
    var header = token.header
      , payload = token.payload;
    
    if (header.alg == 'none') { return cb(new NotValidError('Token unsecured')); }
    
    // Validate the assertion.
    // https://tools.ietf.org/html/draft-sakimura-oidc-structured-token-01#section-3
    // https://tools.ietf.org/html/draft-sakimura-oidc-structured-token-01#section-4
    // http://tools.ietf.org/html/draft-ietf-oauth-jwt-bearer-07#section-3
    //if (!payload.iss) { return cb(new NotValidError('Token missing required claim: iss')); }
    //if (!payload.sub) { return cb(new NotValidError('Token missing required claim: sub')); }
    //if (!payload.aud) { return cb(new NotValidError('Token missing required claim: aud')); }
    //if (!payload.exp) { return cb(new NotValidError('Token missing required claim: exp')); }
    
    var aud = payload.aud;
    if (!Array.isArray(aud)) {
      aud = [ aud ];
    }
    
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
    
    
    function keyed(err, keys) {
      if (err) { return cb(err); }
      
      console.log('GOT KEYS!');
      console.log(keys)
      
      var ok;
      try {
        ok = jws.verify(data, header.alg, keys[0].secret);
      } catch(ex) {
        return cb(ex);
      }
      
      if (!ok) {
        return cb(new NotValidError('Token signature invalid'));
      }
      
      console.log('GOT PAYLOAD');
      console.log(token);
      
      // TODO: Check expiration and all of that stuff.
      
      var tok = {
        issuer: query.sender,
        headers: {
          issuer: token.payload.iss
        },
        claims: token.payload
      }
      
      return cb(null, tok);
      
      return;
      
      var ok;
      try {
        ok = jws.verify(data, header.alg, key);
      } catch(ex) {
        return cb(ex);
      }
      
      if (!ok) {
        return cb(new NotValidError('Token signature invalid'));
      }
      
      console.log('GOT PAYLOAD');
      console.log(token);
      
      // TODO: Normalize header, and return that as another param
      
      return cb(null, token.payload);
      
      
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
    }
    
    
    console.log('!!! SAT DECODE');
    console.log(opts);
    
    console.log('VERIFY JWT SIG');
    console.log(header);
    console.log(payload);
    
    var query  = {
      sender: payload.iss,
      id: header.kid,
      usage: 'verify',
      algorithms: [ 'hmac-sha256' ]
    }
    
    console.log('QUERY WILL BE');
    console.log(query);
    
    keying(query, keyed);
    return;
    
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
