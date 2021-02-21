var Tokens = require('../lib/tokens')
  , Dialects = require('../lib/dialects')
  , sinon = require('sinon');


describe('Tokens', function() {
  
  describe('#validate', function() {
    
    describe('from self', function() {
      var keyring = new Object();
      keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' });
    
      var jwt = {
        parse: function(token) {
          return {
            key: {
              usage: 'decrypt'
            }
          };
        },
        
        unseal: function(token, key, cb) {
          process.nextTick(function() {
            return cb(null, { beep: 'boop' });
          });
        }
      };
      
      jwt.seal = sinon.spy(jwt.seal);
      
    
      var tokens = new Tokens()
        , token;
      
      tokens.use('application/jwt', jwt);
      tokens._keyring = keyring;
      
      before(function(done) {
        tokens.validate('eyJ0.eyJpc3Mi.dBjf', function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should yield token', function() {
        expect(token.claims).to.deep.equal({
          beep: 'boop'
        });
      });
    }); // from self
    
  });
  
});
