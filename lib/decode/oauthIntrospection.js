var uri = require('url')
  , request = require('request')
  , jws = require('jws');


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
    
    
    request.post(url, { form: body }, function handle(err, res, body) {
      console.log('RESPONSE')
      console.log(err);
      if (res) {
        console.log(res.statusCode);
      }
      console.log(body)
      
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
        return cb(new Error('Inactive token'));
      }
      
      // TODO: Validate token (exp, etc)
      
      var token = {};
      token.issuer = json.iss;
      token.subject = json.sub;
      token.audience = json.aud;
      token.scope = json.scope.split(' ');
      token.authorizedPresenter = json.client_id;
      return cb(null, token);
      
    });
    
  };
  
};
