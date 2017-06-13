exports = module.exports = function() {
  
  
  return function interpret(tok, options, cb) {
    console.log('INTERPRET JWT!!!!');
    console.log(tok);
    console.log(options);
    
    var claims = tok.claims;
    if (!(claims.iss || claims.sub || claims.aud)) {
      // not a dialect we understand
      return cb();
    }
    
    console.log('IS A JWT!');
    
    
    var params = {};
    params.subject = { id: claims.sub };
    params.client = { id: claims.cid };
    return cb(null, params);
  };
};
