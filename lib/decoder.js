var debug = require('debug')('tokens')
  , NotValidError = require('./errors/notvaliderror');

function Decoder() {
  this._formats = [];
}

Decoder.prototype.use = function(fn) {
  this._formats.push(fn);
};

Decoder.prototype.decode = function(data, options, cb) {
  if (typeof options == 'function') {
    cb = options;
    options = undefined;
  }
  options = options || {};
  
  var self = this
    , stack = this._formats
    , idx = 0;
  
  function next(err, token, extra) {
    if (err || token) { return cb(err, token, extra); }
    
    var layer = stack[idx++];
    if (!layer) { return cb(new NotValidError('Invalid token')); }
    
    try {
      debug('decode %s', layer.name || 'anonymous');
      var arity = layer.length;
      if (arity == 3) { // async with options
        layer(data, options, next);
      } else if (arity == 2) { // async
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
