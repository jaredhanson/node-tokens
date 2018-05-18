exports = module.exports = function() {
  
  return function translate(ctx, cb) {
    console.log('TRANSLATE TO JWT!');
    console.log(ctx);
    
    
    var claims = {}
      , i, len;
    
    if (ctx.user) {
      claims.sub = ctx.user.id;
    }
    
    if (ctx.permissions) {
      claims.aud = [];
      claims.scp = [];
      
      for (i = 0, len = ctx.permissions.length; i < len; ++i) {
        claims.aud.push(ctx.permissions[i].resource.id);
        claims.scp.push(ctx.permissions[i].scope);
      }
      
      // TODO: Set audience to a string, if single-valued
    }
    
    if (ctx.client) {
      // https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-07#section-4.3
      claims.cid = ctx.client.id;
    }
    
    // https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-07#section-4.2
    
    
    return cb(null, claims);
  };
};
