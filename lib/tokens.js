var Registry = require('./formatregistry')
  , SchemaRegistry = require('./schemaregistry')
  , Sealer = require('./sealer')
  , Unsealer = require('./unsealer2')
  , MultiUnsealer = require('./multiunsealer')
  , Encoder = require('./encoder')
  , Decoder = require('./decoder')
  , none = require('./dialects/none');


function Tokens(dialects, formats) {
  this._formats = new Registry();
  this._schemas = new Registry();
  
  // new stuff
  this._dialects = dialects;
  if (formats) {
    this._formats = formats._formats;
  }
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
  return new Sealer(impl.seal, this._keyring);
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

// TODO: Remove createSerializer, use encode/decode to match Node's querystring
Tokens.prototype.createEncoder = function(type) {
  
  console.log('CREATE ENCODER!');
  console.log(type)
  
  if (type == false) {
    return new Encoder(none.encode);
  }
  
  
  var impl = this._dialects.get(type);
  return new Encoder(impl.encode);
  
  
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

// new stuff
Tokens.prototype.issue = function(msg, options, cb) {
  if (typeof options == 'function') {
    cb = options;
    options = undefined;
  }
  options = options || {};
  
  // TODO: Options for these, at the API level
  var self = this
    , type = 'application/jwt'
    , dialect = options.dialect !== undefined ? options.dialect : 'jwt';
    
  // "syntax" or "scheme" for addressing? (prefer scheme)
  
  //var type = options.type || 'application/jwt';
  //type = 'application/nacl';
  //type = 'application/fe26.2';
  //type = 'application/x-fernet-json';
  //type = 'application/keyczar';
  
  var enc;
  try {
    enc = this.createEncoder(dialect);
  } catch (ex) {
    return cb(ex);
  }
  
  enc.encode(msg, function(err, claims) {
    var sl;
    try {
      sl = self.createSealer(type);
    } catch (ex) {
      return cb(ex);
    }
    
    sl.seal(claims, options, function(err, token) {
      if (err) { return cb(err); }
      return cb(null, token);
    });
  });
};

Tokens.prototype.validate = function(token, options, cb) {
  if (typeof options == 'function') {
    cb = options;
    options = undefined;
  }
  options = options || {};
  
  console.log("VALIDATE THIS TOKEN!");
  console.log(token);
  
  var usl;
  try {
    usl = this.createUnsealer();
  } catch (ex) {
    return cb(ex);
  }
  
  usl.unseal(token, options, function(err, claims, conditions, issuer) {
    console.log('UNSEALED!');
    console.log(err);
    console.log(claims);
    console.log(conditions);
    console.log(issuer);
    
  });
  
};


module.exports = Tokens;
