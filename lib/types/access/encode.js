exports = module.exports = function() {
  
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
    
    return cb(null, claims);
  };
};
