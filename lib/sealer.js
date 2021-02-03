// TODO: Do these need to be here, moved from jwt.seal
var ENCRYPTION_ALGORITHMS = [ 'aes128-cbc-hmac-sha256' ];
var SIGNING_ALGORITHMS = [ 'hmac-sha256', 'rsa-sha256' ];


function Sealer(seal, keyring) {
  this._seal = seal;
  this._keyring = keyring;
}

Sealer.prototype.seal = function(claims, options, cb) {
  //this._seal(msg, to, from, function(err, out) {
  
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
  
  this._keyring.get(undefined, query, function(err, cred) {
    console.log('GOT KEYS');
    console.log(err);
    console.log(cred);
    
    // TODO: pass in key id, params, etc here
    var options = {
      secret: cred.secret
    }
    
    function sealed(err, token) {
      if (err) { return cb(err); }
      return cb(null, token);
    }
    
    var arity = self._seal.length;
    switch (arity) {
    default:
      return self._seal(claims, options, sealed);
    }
  })
};


module.exports = Sealer;
