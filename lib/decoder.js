var debug = require('debug')('tokens');


function Decoder(stack) {
  this._stack = stack;
}

Decoder.prototype.deserialize = 
Decoder.prototype.decode = function(claims, options, cb) {
  if (typeof options == 'function') {
    cb = options;
    options = undefined;
  }
  options = options || {};
  
  
  var stack = this._stack
    , idx = 0;
  
  function next(err, msg) {
    if (err || msg) { return cb(err, msg); }
  
    
  
    var layer = stack[idx++];
    if (!layer) { return cb(new Error('invalid claims')); }
  
    try {
      debug('decode %s', layer.name || 'anonymous');
    
      var arity = layer.decode.length;
      if (arity == 3) { // async with options
        layer.decode(claims, {}, next);
      } else if (arity == 2) { // async
        layer.decode(claims, next);
      } else {
        var m = layer.decode(claims);
        next(null, m);
      }
    } catch (ex) {
      next(ex);
    }
  }
  next();
};


module.exports = Decoder;
