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
    }
    
    request.get(location, handle);
    
  };
  
};
