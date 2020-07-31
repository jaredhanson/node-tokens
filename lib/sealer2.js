function Sealer(seal) {
  this._seal = seal;
}

Sealer.prototype.seal = function(claims, options, cb) {
  //this._seal(msg, to, from, function(err, out) {
    
  function sealed(err, token) {
    if (err) { return cb(err); }
    return cb(null, token);
  }
    
    
  var arity = this._seal.length;
  switch (arity) {
  default:
    return this._seal(claims, options, sealed);
  }
};


module.exports = Sealer;
