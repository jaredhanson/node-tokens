// https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-07#section-2.2.3.1

exports = module.exports = function() {
  
  return {
    decode: function(claims, cb) {
      var msg = {};
      
      return msg;
    },
    
    
    encode: function(msg, cb) {
      var claims = {};
      
      
      // TODO:
      // groups
      // entitlements
      // roles
      
      return claims;
    }
  }
};
