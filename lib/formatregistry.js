function FormatRegistry() {
  this._types = {};
}

FormatRegistry.prototype.getTypes = function() {
  return Object.keys(this._types);
};

FormatRegistry.prototype.add = function(type, impl) {
  this._types[type] = impl;
};

FormatRegistry.prototype.get = function(type) {
  return this._types[type];
};


module.exports = FormatRegistry;
