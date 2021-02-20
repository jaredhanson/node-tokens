function DialectRegistry() {
  this._types = {};
}

DialectRegistry.prototype.getTypes = function() {
  return Object.keys(this._types);
};

DialectRegistry.prototype.use = function(type, impl) {
  this._types[type] = impl;
};

DialectRegistry.prototype.get = function(type) {
  var impl = this._types[type];
  if (!impl) { throw new Error("Unsupported token dialect '" + type + "'"); }
  return impl;
}


module.exports = DialectRegistry;
