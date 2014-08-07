var Encoder = require('./encoder')
  , Decoder = require('./decoder');
  

exports.Encoder = Encoder;
exports.Decoder = Decoder;

exports.decode = {};
exports.decode.sat = require('./decode/sat');
exports.decode.oauthIntrospection = require('./decode/oauthIntrospection');

exports.encode = {};
exports.encode.sat = require('./encode/sat');
