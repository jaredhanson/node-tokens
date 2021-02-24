var debug = require('debug')('tokens');


function MultiUnsealer(stack, keyring) {
  this._stack = stack;
  this._keyring = keyring;
}

MultiUnsealer.prototype.unseal = function(token, options, cb) {
  console.log('MULTI UNSEAL');
  console.log(token);
  console.log(options)
  
  //console.log('TODO: UNSEALING!');
  //return;
  
  var self = this;
  var stack = this._stack
    , idx = 0;

  function next(err, msg, extra) {
    console.log('ATTEMPT UNSEAL: ' + idx);
    console.log(err)
    console.log(msg);
    console.log(extra);
    
    if (err || msg) { return cb(err, msg, extra); }
  
    
  
    var layer = stack[idx++];
    if (!layer) { return cb(new Error('invalid token')); }
    
    var header;
    
    try {
      header = layer.parse(token);
    } catch (ex) {
      // parse error, attempt next
      return next();
    }
    
    if (!header) { return next(); }
    if (header === true) {
      header = {};
    }
    
    
    console.log('PARSED');
    console.log(header);
    
    self._keyring.get(header.issuer, header.key, function(err, key) {
      console.log('GOT KEY');
      console.log(err);
      console.log(key);
      
      try {
        
        var arity = layer.unseal.length;;
        switch (arity) {
        case 3:
          return layer.unseal(token, key, next);
        default:
          return next(null, layer.unseal(token, key));
        }
        
      } catch (ex) {
        return next(ex);
      }
      
    });
  
    /*
    try {
      debug('decode %s', layer.name || 'anonymous');
    
      console.log('TRY DECODE');
      console.log(layer);
    
      var arity = layer.length;
      if (arity == 3) { // async with options
        layer(token, options, next);
      } else if (arity == 2) { // async
        layer(token, next);
      } else {
        var m = layer(token);
        next(null, m);
      }
    } catch (ex) {
      next(ex);
    }
    */
  }
  next();
};


module.exports = MultiUnsealer;
