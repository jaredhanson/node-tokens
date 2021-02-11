var merge = require('utils-merge')
  , Encoder = require('./encoder')


// TODO: Do these need to be here, moved from jwt.seal
var ENCRYPTION_ALGORITHMS = [ 'aes128-cbc-hmac-sha256' ];
var SIGNING_ALGORITHMS = [ 'hmac-sha256', 'rsa-sha256' ];


function Sealer(type, dialect, keyring) {
  this._type = type;
  this._dialect = dialect;
  this._keyring = keyring;
}

Sealer.prototype.seal = function(claims, recipient, options, cb) {
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
  options || {};
    
  
  // TODO: Figure out the expanded API for keyring.  Right now it is is
  //      `recipient, cb`, where recipient is a hostname (undefined meaning "self").
  //       check out NaCL to see their pub/priv key API for inspiration.
  //
  //  Here are some example argument forms for consideration:
  //{
  //        usage: 'sign',
  //        algorithms: [ 'hmac-sha256', 'rsa-sha256' ]
  //      }
  
  var self = this;
  
  function encoded(err, tclaims) {
    if (err) { return cb(err); }
    
    tclaims = tclaims || {};
    claims = merge(tclaims, claims);
  
    function sealed(err, token) {
      if (err) { return cb(err); }
      return cb(null, token);
    }
  
    var confidential = options.confidential !== undefined ? options.confidential : true;
  
    var query  = {
      usage: confidential ? 'encrypt' : 'sign',
      // TODO: Implement way to pass in negotiated algorithms?
      //signingAlgorithms: options.signingAlgorithms
      //algorithms: confidential ? ENCRYPTION_ALGORITHMS : SIGNING_ALGORITHMS
    }
  
    self._keyring.get(recipient, query, function(err, key, sender) {
      function addressed(err, aclaims, header) {
        if (err) { return cb(err); }
      
        aclaims = aclaims || {};
        header = header || {};
        merge(claims, aclaims);
      
        function sealed(err, token) {
          if (err) { return cb(err); }
          return cb(null, token);
        }
    
        var arity = self._type.seal.length;
        switch (arity) {
        case 5:
          return self._type.seal(claims, header, key, options, sealed);
        case 4:
          return self._type.seal(claims, key, options, sealed);
        case 3:
          return self._type.seal(claims, key, sealed);
        }
      }
    
      //console.log(self._type)
    
      // can't do address, thus not federatable.  only for "internal" tokens
      if (!self._dialect || !self._dialect.address) { return addressed(); }
    
      var arity = self._dialect.address.length;
      switch (arity) {
      case 4:
        return self._dialect.address(recipient, sender, options, addressed);
      case 3:
        return addressed(null, self._dialect.address(recipient, sender, options));
      case 2:
        return addressed(null, self._dialect.address(recipient, sender));
      case 1:
        return addressed(null, self._dialect.address(recipient));
      }
    });
  }
  
  if (!this._dialect || !this._dialect.encode) { return encoded(); }
  
  var enc = new Encoder(this._dialect);
  enc.encode(null, options, encoded);
};


module.exports = Sealer;
