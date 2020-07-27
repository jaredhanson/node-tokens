var Registry = require('./formatregistry')
  , SchemaRegistry = require('./schemaregistry')
  , Sealer = require('./sealer2')
  , Unsealer = require('./unsealer2')
  , MultiUnsealer = require('./multiunsealer')
  , Encoder = require('./encoder')
  , Decoder = require('./decoder')


function Tokens() {
  this._formats = new Registry();
  this._schemas = new Registry();
}

Tokens.prototype.format = function(type, impl) {
  this._formats.add(type, impl);
};

Tokens.prototype.dialect = 
Tokens.prototype.schema = function(type, impl) {
  this._schemas.add(type, impl);
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

Tokens.prototype.createSerializer =
Tokens.prototype.createEncoder = function(type) {
  
  console.log('CREATE ENCODER!');
  console.log(type)
  
  var impl = this._schemas.get(type);
  if (!impl) { throw new Error('Unsupported token schema: ' + type); }
  return new Encoder(impl.encode);
  
  // FIXME: below here
  var schemas = this._schemas.get(type)
    , impl;
  console.log(schemas);
  
  if (!schemas) { throw new Error('Unsupported token type: ' + type); }
  
  //if (!schema) {
  //  impl = schemas[schemas.length - 1].impl;
  //}
  
  return new Encoder(impl.encode);
}

/*
Tokens.prototype.createDecoder = function(type) {
  var schemas = this._schemas.get(type)
    , stack = []
    , i, len;
  
  if (!schemas) { throw new Error('Unsupported token type: ' + type); }
  
  for (i = 0, len = schemas.length; i < len; ++i) {
    stack.push(schemas[i].impl.decode);
  }
  return new Decoder(stack);
};
*/

Tokens.prototype.createDeserializer =
Tokens.prototype.createDecoder = function(type) {
  var stack = []
    , types, i, len;
  
  if (!type) {
    types = this._schemas.getTypes();
    for (i = 0, len = types.length; i < len; ++i) {
      stack.push(this._schemas.get(types[i]).decode);
    }
    return new Decoder(stack);
  }
  
  /*
  var impl = this._formats.get(type);
  if (!impl) { throw new Error('Unsupported token format: ' + type); }
  return new Unsealer(impl.unseal);
  */
};


module.exports = Tokens;
