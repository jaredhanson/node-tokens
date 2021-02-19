var merge = require('utils-merge');


function Encoder(dialect, type) {
  this._dialect = dialect;
  this._type = type;
}

Encoder.prototype.encode = function(msg, options, cb) {
  if (typeof options == 'function') {
    cb = options;
    options = undefined;
  }
  options = options || {};
  
  
  var self = this;
  
  function encoded1(err, tclaims) {
    if (err) { return cb(err); }
  
    function encoded(err, claims) {
      if (err) { return cb(err); }
      merge(claims, tclaims);
      return cb(null, claims);
    }
  
    var arity = self._dialect.encode.length;
    switch (arity) {
    case 3:
      return self._dialect.encode(msg, options, encoded);
    case 2:
      return encoded(null, self._dialect.encode(msg, options));
    case 1:
      return encoded(null, self._dialect.encode(msg));
    }
  }
  
  if (!this._type || !this._type.encode) { return encoded1(); }
  
  var enc = new Encoder(this._type);
  enc.encode(msg, options, encoded1);
};


module.exports = Encoder;
