function Encoder() {
  this._formats = {};
}

Encoder.prototype.use = function(name, fn) {
  this._formats[name] = fn;
};

Encoder.prototype.encode = function(format, info, options, cb) {
  if (typeof options == 'function') {
    cb = options;
    options = undefined;
  }
  options = options || {};
  
  var fn = this._formats[format];
  if (!fn) { throw new Error('Token format "' + format + '" is not supported'); }
  
  try {
    var arity = fn.length;
    if (arity == 3) { // async with options
      fn(info, options, cb);
    } else if (arity == 2) { // async
      fn(info, cb);
    } else {
      process.nextTick(function() {
        var t = fn(info);
        cb(null, t);
      });
    }
  } catch (ex) {
    cb(ex);
  }
}


module.exports = Encoder;
