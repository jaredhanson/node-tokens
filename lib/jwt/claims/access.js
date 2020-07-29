exports = module.exports = function() {
  
  return {
    decode: function(claims, cb) {
    },
    
    
    encode: function(msg, cb) {
      var claims = {};
      
      
      if (msg.client) {
        // https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-07#section-4.3
        claims.client_id = msg.client.id;
      }
      
      return claims;
    }
  }
};
