var FormatRegistry = require('./formatregistry')
  , SchemaRegistry = require('./schemaregistry')
  , Sealer = require('./sealer2')
  , Unsealer = require('./unsealer2')
  , MultiUnsealer = require('./multiunsealer')
  , Encoder = require('./encoder');


function Tokens() {
  this._formats = new FormatRegistry();
  this._schemas = new SchemaRegistry();
}

Tokens.prototype.format = function(type, impl) {
  this._formats.add(type, impl);
};

Tokens.prototype.schema = function(schema, type, impl) {
  this._schemas.add(schema, type, impl);
};

Tokens.prototype.createSealer = function(type) {
  var impl = this._formats.get(type);
  if (!impl) { throw new Error('Unsupported token format: ' + type); }
  return new Sealer(impl.seal);
};

Tokens.prototype.createUnsealer = function(type) {
  var stack = []
    , types, i, len;
  
  if (!type) {
    types = this._formats.getTypes();
    for (i = 0, len = types.length; i < len; ++i) {
      stack.push(this._formats.get(types[i]).unseal);
    }
    return new MultiUnsealer(stack);
  }
  
  var impl = this._formats.get(type);
  if (!impl) { throw new Error('Unsupported token format: ' + type); }
  return new Unsealer(impl.unseal);
};

Tokens.prototype.createEncoder = function(schema, type) {
  if (!type) {
    type = schema;
    schema = undefined;
  }
  
  console.log('CREATE ENCODER!');
  console.log(schema);
  console.log(type)
  
  var schemas = this._schemas.get(type)
    , impl;
  console.log(schemas);
  
  if (!schemas) { throw new Error('Unsupported token type: ' + type); }
  
  if (!schema) {
    impl = schemas[schemas.length - 1].impl;
  }
  
  return new Encoder(impl.encode);
}


module.exports = Tokens;
