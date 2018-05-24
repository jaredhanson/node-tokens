exports = module.exports = function() {
  
  return function translate(ctx, cb) {
    var claims = {}
      , i, len;
    
    if (ctx.user) {
      claims.sub = ctx.user.id;
    }
    
    if (ctx.permissions) {
      claims.scope = '';
      
      for (i = 0, len = ctx.permissions.length; i < len; ++i) {
        claims.scope += ctx.permissions[i].scope.join(' ');
      }
    }
    
    if (ctx.client) {
      // https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-07#section-4.3
      claims.client_id = ctx.client.id;
    }
    
    // https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-07#section-4.2
    
    
    return cb(null, claims);
  };
};
