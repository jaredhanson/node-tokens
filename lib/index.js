var Tokens = require('./tokens')
  , Sealer = require('./sealer')
  , Unsealer = require('./unsealer')
  , Translator = require('./translator')
  , Interpreter = require('./interpreter');
  

exports.Tokens = Tokens;

exports.OldSealer = Sealer;
exports.OldUnsealer = Unsealer;
exports.Translator = Translator; // TODO: Remove this
exports.Decoder = // TODO: remove Interpreter as alias
exports.Interpreter = Interpreter;

exports.jwt = {};
exports.jwt.seal = require('./jwt/seal');
exports.jwt.unseal = require('./jwt/unseal');
exports.jwt.translate = require('./jwt/translate');
exports.jwt.interpret = require('./jwt/interpret');

exports.jwt.access = {
  encode: require('./jwt/translate'),
  decode: require('./jwt/interpret')
}


// TODO:
// exports.jose = {};

//exports.decode = {};
//exports.decode.sat = require('./decode/sat');
//exports.decode.oauthIntrospection = require('./decode/oauthIntrospection');

//exports.encode = {};
//exports.encode.sat = require('./encode/sat');
