function Encoder(encode) {
  this._encode = encode;
}

Encoder.prototype.serialize =
Encoder.prototype.encode = function(msg, cb) {
  this._encode(msg, function(err, out) {
    if (err) { return cb(err); }
    return cb(null, out);
  });
};


module.exports = Encoder;
