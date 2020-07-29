var merge = require('deepmerge');


exports = module.exports = function(options) {
  if (Array.isArray(options)) {
    options = { claims: options }
  }
  options = options || [];
  
  var sets = options.claims || [];
  
  
  return {
    decode: function(claims, cb) {
      //if (!(claims.iss || claims.sub || claims.aud)) {
      //if (!(claims.iss || claims.sub || claims.aud)) {
        // not a dialect we understand
        //return cb();
      //}
    
      var msg = {};
      msg.user = { id: claims.sub };
      msg.client = { id: claims.client_id };
      if (claims.scope) {
        msg.scope = claims.scope.split(' ');
      }
      return cb(null, msg);
    },
    
    
    encode: function(msg, cb) {
      var claims = {};
    
      if (msg.user) {
        claims.sub = msg.user.id;
      }
    
      if (msg.scope) {
        claims.scope = msg.scope.join(' ');
      }
    
      // https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-07#section-4.2
    
    
      (function iter(i, err, obj) {
        if (err) { return cb(err); }
        if (obj) {
          claims = merge(claims, obj);
        }
      
        var ext = sets[i]
          , c;
        if (!ext) {
          return cb(null, claims);
        }
      
      
        function next(e, o) {
          iter(i + 1, e, o);
        }
        
        try {
          c = ext.encode(msg);
          next(null, c);
        } catch(ex) {
          return cb(ex);
        }
      })(0);
    }
  }
};
