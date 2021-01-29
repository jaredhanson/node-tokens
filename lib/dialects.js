function Dialects() {
  this._types = {};
}

Dialects.prototype.getTypes = function() {
  return Object.keys(this._types);
};

Dialects.prototype.use = function(type, impl) {
  this._types[type] = impl;
};

Dialects.prototype.get = function(type) {
  var impl = this._types[type];
  if (!impl) { throw new Error("Unsupported token dialect '" + type + "'"); }
  return impl;
}


module.exports = Dialects;
