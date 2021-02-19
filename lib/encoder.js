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
  
  function encoded(err, claims, header) {
    if (err) { return cb(err); }
    
    function encoded2(err, tclaims, theader) {
      if (err) { return cb(err); }
      
      // TODO: dialect should override header?
      merge(claims, tclaims);
      if (theader && !header) { header = {}; }
      merge(header, theader);
      return cb(null, claims, header);
    }
    
    if (!self._type || !self._type.encode) { return encoded2(); }
    
    var enc = new Encoder(self._type);
    enc.encode(msg, options, encoded2);
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
};


module.exports = Encoder;
