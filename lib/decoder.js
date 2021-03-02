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
      var arity = layer.decode.length;
      switch (arity) {
      case 1:
        return next(null, layer.decode(claims));
      }
    } catch (ex) {
      next(ex);
    }
  }
  next();
};


module.exports = Decoder;
