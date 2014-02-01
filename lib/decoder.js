var debug = require('debug')('tokens');

function Decoder() {
  this._formats = [];
}

Decoder.prototype.use = function(fn) {
  this._formats.push(fn);
};

Decoder.prototype.decode = function(data, cb) {
  var self = this
    , stack = this._formats
    , idx = 0;
  
  function next(err, token) {
    if (err || token) { return cb(err, token); }
    
    var layer = stack[idx++];
    if (!layer) { return cb(new Error('Failed to decode token')); }
    
    try {
      debug('decode %s', layer.name || 'anonymous');
      var arity = layer.length;
      if (arity == 2) { // async
        layer(data, next);
      } else {
        var t = layer(data);
        next(null, t);
      }
    } catch (ex) {
      next(ex);
    }
  }
  next();
};


module.exports = Decoder;
