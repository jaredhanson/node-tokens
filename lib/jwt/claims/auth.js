exports = module.exports = function() {
  
  return {
    decode: function(claims, cb) {
      var msg = {};
      
      return msg;
    },
    
    
    encode: function(msg, cb) {
      var claims = {};
      
      // TODO: https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-07
      // auth_time, acr, amr
      
      return claims;
    }
  }
};
