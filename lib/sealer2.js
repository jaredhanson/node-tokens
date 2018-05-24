function Sealer(seal) {
  this._seal = seal;
}

Sealer.prototype.seal = function(claims, recipients, options, cb) {
  //this._seal(msg, to, from, function(err, out) {
    
  function sealed(err, token) {
    if (err) { return cb(err); }
    return cb(null, token);
  }
    
    
  var arity = this._seal.length;
  switch (arity) {
  case 4:
    return this._seal(claims, recipients, options, sealed);
  default:
    return this._seal(claims, recipients, sealed);
  }
};


module.exports = Sealer;
