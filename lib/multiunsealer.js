var debug = require('debug')('tokens');


function MultiUnsealer(stack) {
  this._stack = stack;
}

MultiUnsealer.prototype.unseal = function(token, cb) {
  console.log('MULTI UNSEAL');
  console.log(token);
  
  var stack = this._stack
    , idx = 0;
    
  console.log(stack)

  function next(err, msg, extra) {
    console.log('ATTEMPT UNSEAL: ' + idx);
    console.log(err)
    console.log(msg);
    
    if (err || msg) { return cb(err, msg, extra); }
  
    
  
    var layer = stack[idx++];
    if (!layer) { console.log('no layer'); return cb(new Error('invalid token')); }
    console.log('LAYER?');
    console.log(layer);
    console.log(layer.length);
  
    try {
      debug('decode %s', layer.name || 'anonymous');
    
      console.log('TRY DECODE');
      console.log(layer);
    
      var arity = layer.length;
      if (arity == 3) { // async with options
        layer(token, {}, next);
      } else if (arity == 2) { // async
        layer(token, next);
      } else {
        var m = layer(token);
        next(null, m);
      }
    } catch (ex) {
      next(ex);
    }
  }
  next();
};


module.exports = MultiUnsealer;
