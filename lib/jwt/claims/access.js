exports = module.exports = function() {
  
  return {
    decode: function(claims, cb) {
      var msg = {};
      
      msg.client = { id: claims.client_id };
      
      if (claims.scope) {
        msg.scope = claims.scope.split(' ');
      }
      
      return msg;
    },
    
    
    encode: function(msg, cb) {
      var claims = {};
      
      
      if (msg.client) {
        // https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-07#section-4.3
        claims.client_id = msg.client.id;
      }
      if (msg.scope) {
        claims.scope = msg.scope.join(' ');
      }
      
      return claims;
    }
  }
};
