var merge = require('utils-merge');

exports.decode = function(claims) {
  var msg = merge({}, claims);
  return msg;
};
    
exports.encode = function(msg) {
  var claims = merge({}, msg);
  return claims;
};
