function Interpreter() {
  this._set = [];
}

Interpreter.prototype.use = function(dialect, impl) {
  if (typeof dialect == 'function') {
    impl = dialect;
    dialect = undefined;
  }
  this._set.push({ dialect: dialect, impl: impl });
};

Interpreter.prototype.interpret = function(tok, options, cb) {
  if (typeof options == 'function') {
    cb = options;
    options = undefined;
  }
  options = options || {};
  
  var self = this
    , set = this._set
    , i = 0;
  function next(err, claims) {
    if (err || claims) { return cb(err, claims); }
  
    var entry = set[i++]
      , impl;
    // TODO: Make a better error, with a status code
    if (!entry) { return cb(new Error('Failed to interpret token')); }
  
    if (options.dialect && options.dialect != entry.dialect) {
      return next();
    }
  
    impl = entry.impl;
    try {
      var arity = impl.length;
      if (arity == 3) { // async with options
        impl(tok, options, next);
      } else if (arity == 2) { // async
        impl(tok, next);
      } else {
        var rv = impl(tok);
        next(null, rv);
      }
    } catch (ex) {
      next(ex);
    }
  }
  next();
}


module.exports = Interpreter;
