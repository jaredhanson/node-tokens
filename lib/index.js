var Tokens = require('./tokens')
  , Dialects = require('./dialects')
  , Unsealer = require('./unsealer')
  , Translator = require('./translator')
  , Interpreter = require('./interpreter');
  

exports.Dialects = Dialects;
exports.Tokens = Tokens;

exports.OldUnsealer = Unsealer;
exports.Translator = Translator; // TODO: Remove this
exports.Decoder = // TODO: remove Interpreter as alias
exports.Interpreter = Interpreter;

exports.jwt = {};
exports.jwt.seal = require('./jwt/seal');
exports.jwt.unseal = require('./jwt/unseal');

exports.jwt.dialect = require('./jwt/dialect');
exports.jwt.claims = {};
exports.jwt.claims.access = require('./jwt/claims/access');
exports.jwt.claims.auth = require('./jwt/claims/auth');
exports.jwt.claims.identity = require('./jwt/claims/identity');


// TODO:
// exports.jose = {};

//exports.decode = {};
//exports.decode.sat = require('./decode/sat');
//exports.decode.oauthIntrospection = require('./decode/oauthIntrospection');

//exports.encode = {};
//exports.encode.sat = require('./encode/sat');
