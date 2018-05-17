function SchemaRegistry() {
  this._types = {};
}

SchemaRegistry.prototype.add = function(schema, type, impl) {
  var arr = this._types[type] || [];
  arr.push({ schema: schema, impl: impl });
  this._types[type] = arr;
};

SchemaRegistry.prototype.get = function(type) {
  return this._types[type];
};


module.exports = SchemaRegistry;
