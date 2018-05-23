function Registry() {
  this._types = {};
}

Registry.prototype.getTypes = function() {
  return Object.keys(this._types);
};

Registry.prototype.add = function(type, impl) {
  this._types[type] = impl;
};

Registry.prototype.get = function(type) {
  return this._types[type];
};


module.exports = Registry;
