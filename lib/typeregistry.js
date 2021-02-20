function TypeRegistry() {
  this._types = {};
}

TypeRegistry.prototype.getTypes = function() {
  return Object.keys(this._types);
};

TypeRegistry.prototype.use = function(type, impl) {
  this._types[type] = impl;
};

TypeRegistry.prototype.get = function(type) {
  var impl = this._types[type];
  if (!impl) { throw new Error("Unsupported token type '" + type + "'"); }
  return impl;
};


module.exports = TypeRegistry;
