exports = module.exports = function(options) {
  options = options || [];
  
  var extensions = options.extensions || [];
  
  
  return function jwt(msg, cb) {
    var claims = {};
    
    if (msg.user) {
      claims.sub = msg.user.id;
    }
    
    if (msg.scope) {
      claims.scope = msg.scope.join(' ');
    }
    
    if (msg.client) {
      // https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-07#section-4.3
      claims.client_id = msg.client.id;
    }
    
    // https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-07#section-4.2
    
    
    (function iter(i, err, obj) {
      if (err) { return cb(err); }
      
      var extension = extensions[i];
      if (!extension) {
        return cb(null, claims);
      }
      
      
      function next(e, o) {
        iter(i + 1, e, o);
      }
      
      try {
        layer(user, next);
      } catch(ex) {
        return cb(ex);
      }
    })(0);
  };
};
