var debug = require('debug')('tokens');


function Decoder(stack) {
  this._stack = stack;
}

Decoder.prototype.decode = function(claims, cb) {
  console.log('MULTI DECODE');
  console.log(claims);
  
  var stack = this._stack
    , idx = 0;
    
  console.log(stack)

  function next(err, msg) {
    console.log('ATTEMPT DECODE: ' + idx);
    console.log(err)
    console.log(msg);
    
    if (err || msg) { return cb(err, msg); }
  
    
  
    var layer = stack[idx++];
    if (!layer) { console.log('no layer'); return cb(new Error('invalid claims')); }
    console.log('LAYER?');
    console.log(layer);
    console.log(layer.length);
  
    try {
      debug('decode %s', layer.name || 'anonymous');
    
      console.log('TRY DECODE');
      console.log(layer);
    
      var arity = layer.length;
      if (arity == 3) { // async with options
        layer(claims, {}, next);
      } else if (arity == 2) { // async
        layer(claims, next);
      } else {
        var m = layer(claims);
        next(null, m);
      }
    } catch (ex) {
      next(ex);
    }
  }
  next();
};


module.exports = Decoder;
