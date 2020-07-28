exports = module.exports = function() {
  
  return function jwt(claims, cb) {
    //if (!(claims.iss || claims.sub || claims.aud)) {
    //if (!(claims.iss || claims.sub || claims.aud)) {
      // not a dialect we understand
      //return cb();
    //}
    
    var msg = {};
    msg.user = { id: claims.sub };
    msg.client = { id: claims.client_id };
    if (claims.scope) {
      msg.scope = claims.scope.split(' ');
    }
    return cb(null, msg);
  };
};
