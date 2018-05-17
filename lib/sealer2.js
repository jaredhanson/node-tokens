function Sealer(seal) {
  this._seal = seal;
}

Sealer.prototype.seal = function(msg, to, from, cb) {
  this._seal(msg, to, from, function(err, out) {
    if (err) { return cb(err); }
    return cb(null, out);
  });
};


module.exports = Sealer;
