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
      //return cb(null, msg);
      
      (function iter(i, err, obj) {
        if (err) { return cb(err); }
        if (obj) {
          msg = merge(msg, obj);
        }
        
        var ext = sets[i]
          , m;
        if (!ext) {
          return cb(null, msg);
        }
      
      
        function next(e, o) {
          iter(i + 1, e, o);
        }
        
        try {
          m = ext.decode(claims);
          next(null, m);
        } catch(ex) {
          return cb(ex);
        }
      })(0);
    },
    
    
    encode: function(msg, cb) {
      var claims = {};
    
      if (msg.user) {
        claims.sub = msg.user.id;
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
