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
      
      jwt.parse = sinon.spy(jwt.parse);
      jwt.unseal = sinon.spy(jwt.unseal);
      
    
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
      
      it('should parse token', function() {
        expect(jwt.parse.callCount).to.equal(1);
        var call = jwt.parse.getCall(0);
        expect(call.args[0]).to.equal('eyJ0.eyJpc3Mi.dBjf');
      });
      
      it('should query for key', function() {
        expect(keyring.get.callCount).to.equal(1);
        var call = keyring.get.getCall(0);
        expect(call.args[0]).to.be.undefined;
        expect(call.args[1]).to.deep.equal({
          usage: 'decrypt'
        });
      });
      
      it('should unseal token', function() {
        expect(jwt.unseal.callCount).to.equal(1);
        var call = jwt.unseal.getCall(0);
        expect(call.args[0]).to.equal('eyJ0.eyJpc3Mi.dBjf');
        expect(call.args[1]).to.deep.equal({
          secret: 'keyboardcat'
        });
      });
      
      it('should yield token', function() {
        expect(token.claims).to.deep.equal({
          beep: 'boop'
        });
      });
    }); // from self
    
    describe('from issuer', function() {
      var keyring = new Object();
      keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' });
    
      var jwt = {
        parse: function(token) {
          return {
            issuer: 'example.com',
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
      
      jwt.parse = sinon.spy(jwt.parse);
      jwt.unseal = sinon.spy(jwt.unseal);
      
    
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
      
      it('should parse token', function() {
        expect(jwt.parse.callCount).to.equal(1);
        var call = jwt.parse.getCall(0);
        expect(call.args[0]).to.equal('eyJ0.eyJpc3Mi.dBjf');
      });
      
      it('should query for key', function() {
        expect(keyring.get.callCount).to.equal(1);
        var call = keyring.get.getCall(0);
        expect(call.args[0]).to.equal('example.com');
        expect(call.args[1]).to.deep.equal({
          usage: 'decrypt'
        });
      });
      
      it('should unseal token', function() {
        expect(jwt.unseal.callCount).to.equal(1);
        var call = jwt.unseal.getCall(0);
        expect(call.args[0]).to.equal('eyJ0.eyJpc3Mi.dBjf');
        expect(call.args[1]).to.deep.equal({
          secret: 'keyboardcat'
        });
      });
      
      it('should yield token', function() {
        expect(token.claims).to.deep.equal({
          beep: 'boop'
        });
      });
    }); // from issuer
    
    describe('from issuer as object', function() {
      var keyring = new Object();
      keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' });
    
      var jwt = {
        parse: function(token) {
          return {
            issuer: {
              identifier: 'https://example.com/'
            },
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
      
      jwt.parse = sinon.spy(jwt.parse);
      jwt.unseal = sinon.spy(jwt.unseal);
      
    
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
      
      it('should parse token', function() {
        expect(jwt.parse.callCount).to.equal(1);
        var call = jwt.parse.getCall(0);
        expect(call.args[0]).to.equal('eyJ0.eyJpc3Mi.dBjf');
      });
      
      it('should query for key', function() {
        expect(keyring.get.callCount).to.equal(1);
        var call = keyring.get.getCall(0);
        expect(call.args[0]).to.deep.equal({
          identifier: 'https://example.com/' 
        });
        expect(call.args[1]).to.deep.equal({
          usage: 'decrypt'
        });
      });
      
      it('should unseal token', function() {
        expect(jwt.unseal.callCount).to.equal(1);
        var call = jwt.unseal.getCall(0);
        expect(call.args[0]).to.equal('eyJ0.eyJpc3Mi.dBjf');
        expect(call.args[1]).to.deep.equal({
          secret: 'keyboardcat'
        });
      });
      
      it('should yield token', function() {
        expect(token.claims).to.deep.equal({
          beep: 'boop'
        });
      });
    }); // from issuer as object
    
    describe('with dialects', function() {
      
      describe.skip('from issuer as object', function() {
        var keyring = new Object();
        keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' });
    
        var access = {
          decode: function(msg) {
            return {
              scp: msg.scope
            };
          }
        };
        
        access.decode = sinon.spy(access.decode);
        
        var dialects = new Dialects();
        dialects.use('application/at+jwt', access);
    
        var jwt = {
          parse: function(token) {
            return {
              issuer: {
                identifier: 'https://example.com/'
              },
              key: {
                usage: 'decrypt'
              }
            };
          },
        
          unseal: function(token, key, cb) {
            process.nextTick(function() {
              return cb(null, { scp: 'profile' });
            });
          }
        };
      
        jwt.parse = sinon.spy(jwt.parse);
        jwt.unseal = sinon.spy(jwt.unseal);
      
    
        var tokens = new Tokens(dialects)
          , token;
      
        tokens.use('application/jwt', jwt);
        tokens._keyring = keyring;
      
        before(function(done) {
          tokens.validate('eyJ0.eyJpc3Mi.dBjf', function(err, t) {
            token = t;
            done(err);
          });
        });
      
        it('should parse token', function() {
          expect(jwt.parse.callCount).to.equal(1);
          var call = jwt.parse.getCall(0);
          expect(call.args[0]).to.equal('eyJ0.eyJpc3Mi.dBjf');
        });
      
        it('should query for key', function() {
          expect(keyring.get.callCount).to.equal(1);
          var call = keyring.get.getCall(0);
          expect(call.args[0]).to.deep.equal({
            identifier: 'https://example.com/' 
          });
          expect(call.args[1]).to.deep.equal({
            usage: 'decrypt'
          });
        });
      
        it('should unseal token', function() {
          expect(jwt.unseal.callCount).to.equal(1);
          var call = jwt.unseal.getCall(0);
          expect(call.args[0]).to.equal('eyJ0.eyJpc3Mi.dBjf');
          expect(call.args[1]).to.deep.equal({
            secret: 'keyboardcat'
          });
        });
      
        it('should yield token', function() {
          expect(token.claims).to.deep.equal({
            scp: 'profile'
          });
        });
      }); // from issuer as object
      
    }); // with dialects
    
  });
  
});
