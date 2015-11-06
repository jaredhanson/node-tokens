var uri = require('url')
  , request = require('request')
  , moment = require('moment')
  , jws = require('jws')
  , NotValidError = require('../errors/notvaliderror');


// https://tools.ietf.org/html/rfc7662
module.exports = function(url, options) {
  options = options || {};
  var clientID = options.clientID;
  
  return function oauthIntrospection(data, opts, cb) {
    if (typeof opts == 'function') {
      cb = opts;
      opts = undefined;
    }
    opts = opts || {};
    
    var body = { token: data };
    // TODO: Token type hint
    
    // TODO: Implement an extensible mechanism to supply credentials with the request
    /*
    if (options.key) {
      var now = Math.floor(Date.now() / 1000);
      var header = { typ: 'JWT', alg: 'RS256' };
      var payload = {
        iss: clientID,
        sub: clientID,
        aud: url,
        exp: now + 120,
        iat: now
      };
      
      var assertion = jws.sign({ header: header, payload: payload, secret: options.key });
      body.client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
      body.client_assertion = assertion;
    }
    */
    
    
    request.post(url, { form: body }, function handle(err, res, body) {
      if (err) { return cb(err); }
      if (res.statusCode != 200) {
        // TODO: Parse error response
        return cb(new Error('Failed token introspection with status code: ' + res.statusCode));
      }
      
      var json;
      try {
        json = JSON.parse(body);
      } catch (ex) {
        return cb(new Error('Unable to parse token introspection response'));
      }
      
      if (!json.active) {
        return cb(new NotValidError('Token not active'));
      }
      
      var token = {};
      token.issuer = json.iss;
      token.subject = json.sub;
      token.username = json.username;
      token.audience = json.aud;
      if (typeof token.audience == 'string') {
        token.audience = [ token.audience ];
      }
      token.authorizedParty =
      token.authorizedPresenter = json.client_id;
      if (json.scope) {
        token.scope = json.scope.split(' ');
      }
      
      if (json.iat) {
        token.issuedAt = moment.unix(json.iat).toDate();
      }
      if (json.exp) {
        token.expiresAt = moment.unix(json.exp).toDate();
      }
      if (json.nbf) {
        token.notBefore = moment.unix(json.nbf).toDate();
      }
      
      token.id = json.jti;
      token.tokenType = json.token_type;
      
      return cb(null, token);
    });
  };
};
