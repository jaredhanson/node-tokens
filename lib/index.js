var Encoder = require('./encoder')
  , Decoder = require('./decoder');
  

exports.Sealer = Encoder;
exports.Unsealer = Decoder;

exports.jwt = {};
exports.jwt.seal = require('./encode/sat');
exports.jwt.unseal = require('./decode/sat');

//exports.decode = {};
//exports.decode.sat = require('./decode/sat');
//exports.decode.oauthIntrospection = require('./decode/oauthIntrospection');

//exports.encode = {};
//exports.encode.sat = require('./encode/sat');
