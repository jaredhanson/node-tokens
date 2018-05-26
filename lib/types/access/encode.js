exports = module.exports = function() {
  
  return function jwt(msg, cb) {
    var claims = {}
      , i, len;
    
    if (msg.user) {
      claims.sub = msg.user.id;
    }
    
    if (msg.permissions) {
      claims.scope = '';
      for (i = 0, len = msg.permissions.length; i < len; ++i) {
        claims.scope += msg.permissions[i].scope.join(' ');
      }
    }
    
    if (msg.client) {
      // https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-07#section-4.3
      claims.client_id = msg.client.id;
    }
    
    // https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-07#section-4.2
    
    return cb(null, claims);
  };
};
