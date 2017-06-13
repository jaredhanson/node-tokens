var Sealer = require('./sealer')
  , Unsealer = require('./unsealer')
  , Translator = require('./translator')
  , Interpreter = require('./interpreter');
  

exports.Sealer = Sealer;
exports.Unsealer = Unsealer;
exports.Translator = Translator;
exports.Interpreter = Interpreter;

exports.jwt = {};
exports.jwt.seal = require('./jwt/seal');
exports.jwt.unseal = require('./jwt/unseal');
exports.jwt.translate = require('./jwt/translate');
exports.jwt.interpret = require('./jwt/interpret');

// TODO:
// exports.jose = {};

//exports.decode = {};
//exports.decode.sat = require('./decode/sat');
//exports.decode.oauthIntrospection = require('./decode/oauthIntrospection');

//exports.encode = {};
//exports.encode.sat = require('./encode/sat');
