function Encoder(dialect) {
  this._dialect = dialect;
}

Encoder.prototype.encode = function(msg, options, cb) {
  if (typeof options == 'function') {
    cb = options;
    options = undefined;
  }
  options = options || {};
  
  function encoded(err, claims) {
    if (err) { return cb(err); }
    return cb(null, claims);
  }
  
  var arity = this._dialect.encode.length;
  switch (arity) {
  case 3:
    return this._dialect.encode(msg, options, encoded);
  case 2:
    return encoded(null, this._dialect.encode(msg, options));
  case 1:
    return encoded(null, this._dialect.encode(msg));
  }
};


module.exports = Encoder;
