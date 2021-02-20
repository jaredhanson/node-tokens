var TypeRegistry = require('./typeregistry')
  , Sealer = require('./sealer')
  , Unsealer = require('./unsealer2')
  , MultiUnsealer = require('./multiunsealer')
  , Encoder = require('./encoder')
  , Decoder = require('./decoder')
  , none = require('./dialects/none');


function Tokens(dialects, formats) {
  this._formats = new TypeRegistry();
  this._schemas = new TypeRegistry();
  
  // new stuff
  this._dialects = dialects;
  if (formats) {
    this._formats = formats._formats;
  }
}

Tokens.prototype.format = 
Tokens.prototype.use = function(type, impl) {
  this._formats.use(type, impl);
};

Tokens.prototype.createSealer = function(type, dialect) {
  dialect = dialect || type;
  
  var impl = this._formats.get(type);
  
  var dimpl;
  try {
    dimpl = this._dialects.get(type);
  } catch (ex) {
    return new Sealer(impl, null, this._keyring);;
  }
  
  return new Sealer(impl, dimpl, this._keyring);
};

Tokens.prototype.createUnsealer = function(type) {
  var stack = []
    , types, i, len;
  
  if (!type) {
    types = this._formats.getTypes();
    for (i = 0, len = types.length; i < len; ++i) {
      stack.push([this._formats.get(types[i]).unseal, this._formats.get(types[i]).parse]);
    }
    return new MultiUnsealer(stack, this._keyring);
  }
  
  var impl = this._formats.get(type);
  if (!impl) { throw new Error('Unsupported token format: ' + type); }
  return new Unsealer(impl.unseal);
};

// TODO: Remove createSerializer, use encode/decode to match Node's querystring
Tokens.prototype.createEncoder = function(type, type2) {
  if (!this._dialects) {
    return new Encoder(none);
  }
  
  if (type == false) {
    return new Encoder(none);
  }
  
  var impl = this._dialects.get(type)
    , dimpl;
  if (type2) {
    try {
      dimpl = this._dialects.get(type2);
    } catch (ex) {
      return new Encoder(impl);
    }
  }
  
  return new Encoder(impl, dimpl);
}

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
Tokens.prototype.issue = function(msg, recipient, options, cb) {
  if (typeof recipient == 'function') {
    cb = recipient;
    options = undefined;
    recipient = undefined;
  }
  if (typeof recipient == 'object' && typeof options == 'function') {
    cb = options;
    options = recipient;
    recipient = undefined;
  }
  if (typeof options == 'function') {
    cb = options;
    options = undefined;
  }
  options = options || {};
  
  // TODO: Options for these, at the API level
  var self = this
    , type = options.type || 'application/jwt'
    , dialect = options.dialect !== undefined ? options.dialect : 'application/jwt';
    
    // TODO: Default ttl option
    
  // "syntax" or "scheme" for addressing? (prefer scheme)
  
  var type = options.type || 'application/jwt';
  //type = 'application/nacl';
  //type = 'application/fe26.2';
  //type = 'application/x-fernet-json';
  //type = 'application/keyczar';
  //type = 'application/swt';
  
  var enc;
  try {
    enc = this.createEncoder(dialect, type);
  } catch (ex) {
    return cb(ex);
  }
  
  enc.encode(msg, options, function(err, claims, header) {
    if (err) { return cb(err); }
    
    var sl;
    try {
      sl = self.createSealer(type);
    } catch (ex) {
      return cb(ex);
    }
    
    if (header) {
      claims = {
        claims: claims,
        header: header
      }
    }
    
    sl.seal(claims, recipient, options, function(err, token) {
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
  
  // TODO: Clean up the arguments here
  usl.unseal(token, options, function(err, claims, conditions, issuer) {
    console.log('UNSEALED!');
    console.log(err);
    console.log(claims);
    console.log(conditions);
    console.log(issuer);
    
    if (err) { return cb(err); }
    
    // TODO: parse the claims with dialects into a message
    
    return cb(null, claims);
    
  });
  
};


module.exports = Tokens;
