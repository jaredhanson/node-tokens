var SchemaRegistry = require('./schemaregistry')
  , Encoder = require('./encoder');


function Tokens() {
  this._schemas = new SchemaRegistry();
}

Tokens.prototype.schema = function(schema, type, impl) {
  this._schemas.add(schema, type, impl);
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
