var uri = require('url')
  , request = require('request')
  , jwt = require('jws');


module.exports = function(url) {
  
  return function oauthIntrospection(data, cb) {
    console.log('OAUTH INTROSPECT');
    console.log(data);
    
    var u = uri.parse(url, true);
    u.query.token = data;
    delete u.search;
    var location = uri.format(u);
    
    console.log('QUERY: ');
    console.log(location);
    
    function handle(err, res, body) {
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
      
    }
    
    request.get(location, handle);
    
  };
  
};
