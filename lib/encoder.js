function Encoder(encode) {
  this._encode = encode;
}

Encoder.prototype.encode = function(msg, cb) {
  function encoded(err, claims) {
    if (err) { return cb(err); }
    return cb(null, claims);
  }
  
  var arity = this._encode.length;
  switch (arity) {
  case 2:
    return this._encode(msg, encoded);
  case 1:
    return encoded(null, this._encode(msg));
  }
};


module.exports = Encoder;
