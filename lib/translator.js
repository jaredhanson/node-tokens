function Translator() {
  this._dialects = {};
}

Translator.prototype.use = function(dialect, impl) {
  this._dialects[dialect] = impl;
};

Translator.prototype.translate = function(ctx, options, cb) {
  if (typeof options == 'function') {
    cb = options;
    options = undefined;
  }
  options = options || {};
  
  var dialect = options.dialect || 'urn:ietf:params:oauth:token-type:jwt';
  var impl = this._dialects[dialect];
  if (!impl) { return cb(new Error('Token dialect "' + dialect + '" is not supported')); }
  
  try {
    var arity = impl.length;
    if (arity == 3) { // async with options
      impl(ctx, options, cb);
    } else if (arity == 2) { // async
      impl(ctx, cb);
    } else {
      process.nextTick(function() {
        var rv = impl(ctx);
        cb(null, rv);
      });
    }
  } catch (ex) {
    cb(ex);
  }
};


module.exports = Translator;
