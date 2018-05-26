function Unsealer(unseal) {
  this._unseal = unseal;
}

Unsealer.prototype.unseal = function(token, options, cb) {
  this._unseal(token, function(err, out) {
    if (err) { return cb(err); }
    return cb(null, out);
  });
};


module.exports = Unsealer;
