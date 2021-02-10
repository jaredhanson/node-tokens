var merge = require('utils-merge');


// TODO: Do these need to be here, moved from jwt.seal
var ENCRYPTION_ALGORITHMS = [ 'aes128-cbc-hmac-sha256' ];
var SIGNING_ALGORITHMS = [ 'hmac-sha256', 'rsa-sha256' ];


function Sealer(type, dialect, keyring) {
  this._type = type;
  this._dialect = dialect;
  this._keyring = keyring;
}

Sealer.prototype.seal = function(claims, recipient, options, cb) {
  //this._seal(msg, to, from, function(err, out) {
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
    
  function sealed(err, token) {
    if (err) { return cb(err); }
    return cb(null, token);
  }
    
  /*  
  var arity = this._seal.length;
  switch (arity) {
  default:
    return this._seal(claims, options, sealed);
  }
  */
  
  console.log('SEALER USING KEYRING...');
  
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
  
  var confidential = options.confidential !== undefined ? options.confidential : true;
  
  var query  = {
    usage: confidential ? 'encrypt' : 'sign',
    // TODO: Implement way to pass in negotiated algorithms?
    //signingAlgorithms: options.signingAlgorithms
    //algorithms: confidential ? ENCRYPTION_ALGORITHMS : SIGNING_ALGORITHMS
  }
  
  this._keyring.get(recipient, query, function(err, key, sender) {
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
      case 4:
        return self._type.seal(claims, key, options, sealed);
      case 3:
        return self._type.seal(claims, key, sealed);
      }
    }
    
    //console.log(self._type)
    
    if (!self._dialect || !self._dialect.address) { return addressed(); }
    
    console.log('ADDRESSING!');
    
    var arity = self._dialect.address.length;
    switch (arity) {
    case 1:
      return addressed(null, self._dialect.address(recipient));
    }
  });
};


module.exports = Sealer;
