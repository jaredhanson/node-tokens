function Unsealer(unseal) {
  this._unseal = unseal;
}

Unsealer.prototype.unseal = function(token, cb) {
  this._unseal(token, function(err, out) {
    if (err) { return cb(err); }
    return cb(null, out);
  });
};


module.exports = Unsealer;
