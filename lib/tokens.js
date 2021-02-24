var TypeRegistry = require('./typeregistry')
  , Sealer = require('./sealer')
  , Unsealer = require('./unsealer2')
  , MultiUnsealer = require('./multiunsealer')
  , Encoder = require('./encoder')
  , Decoder = require('./decoder')
  , none = require('./dialects/none');


function Tokens(dialects, formats) {
  this._formats = new TypeRegistry();
  
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
  
  var typ = this._formats.get(type)
    , dlct;
  try {
    dlct = this._dialects.get(type);
  } catch (ex) {
    return new Sealer(typ, null, this._keyring);;
  }
  
  return new Sealer(typ, dlct, this._keyring);
};

Tokens.prototype.createUnsealer = function(type) {
  var stack = []
    , types, i, len;
  
  if (!type) {
    types = this._formats.getTypes();
    for (i = 0, len = types.length; i < len; ++i) {
      stack.push(this._formats.get(types[i]));
    }
    
    return new MultiUnsealer(stack, this._keyring);
  }
  
  var impl = this._formats.get(type);
  if (!impl) { throw new Error('Unsupported token format: ' + type); }
  return new Unsealer(impl.unseal);
};

// TODO: Remove createSerializer, use encode/decode to match Node's querystring
Tokens.prototype.createEncoder = function(dialect, type) {
  if (!this._dialects) {
    return new Encoder(none);
  }
  
  var dlct = (dialect !== false ? this._dialects.get(dialect) : none)
    , tdlct;
  if (type) {
    try {
      tdlct = this._dialects.get(type);
    } catch (ex) {
      return new Encoder(dlct);
    }
  }
  
  return new Encoder(dlct, tdlct);
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
    
    return cb(null, { claims: claims });
    
  });
  
};


module.exports = Tokens;
