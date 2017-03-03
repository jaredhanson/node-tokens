function Encoder() {
  this._formats = {};
}

Encoder.prototype.use = function(name, fn) {
  this._formats[name] = fn;
};

Encoder.prototype.seal = 
Encoder.prototype.encode = function(claims, options, cb) {
  if (typeof options == 'function') {
    cb = options;
    options = undefined;
  }
  options = options || {};
  
  var type = options.type || 'application/jwt';
  var fn = this._formats[type];
  if (!fn) { throw new Error('Token format "' + format + '" is not supported'); }
  
  try {
    var arity = fn.length;
    if (arity == 3) { // async with options
      fn(claims, options, cb);
    } else if (arity == 2) { // async
      fn(claims, cb);
    } else {
      process.nextTick(function() {
        var t = fn(claims);
        cb(null, t);
      });
    }
  } catch (ex) {
    cb(ex);
  }
}


module.exports = Encoder;
