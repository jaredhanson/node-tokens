var Tokens = require('../lib/tokens')
  , Dialects = require('../lib/dialects')
  , sinon = require('sinon');


describe('Tokens', function() {
  
  describe('#issue', function() {
  
    describe('to self', function() {
      var keyring = new Object();
      keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' });
    
      var jwt = {
        seal: function(claims, key, cb) {
          process.nextTick(function() {
            return cb(null, 'eyJ0.eyJpc3Mi.dBjf');
          });
        }
      };
      
      jwt.seal = sinon.spy(jwt.seal);
      
    
      var tokens = new Tokens()
        , token;
      
      tokens.use('application/jwt', jwt);
      tokens._keyring = keyring;
      
      before(function(done) {
        tokens.issue({ beep: 'boop' }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keyring.get.callCount).to.equal(1);
        var call = keyring.get.getCall(0);
        expect(call.args[0]).to.be.undefined;
        expect(call.args[1]).to.deep.equal({
          usage: 'encrypt'
        });
      });
      
      it('should seal message', function() {
        expect(jwt.seal.callCount).to.equal(1);
        var call = jwt.seal.getCall(0);
        expect(call.args[0]).to.deep.equal({
          beep: 'boop'
        });
        expect(call.args[1]).to.deep.equal({
          secret: 'keyboardcat'
        });
      });
      
      it('should yield token', function() {
        expect(token).to.equal('eyJ0.eyJpc3Mi.dBjf');
      });
    }); // to self
    
    describe('to self with ttl option', function() {
      var keyring = new Object();
      keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' });
    
      var jwt = {
        seal: function(claims, key, options, cb) {
          process.nextTick(function() {
            return cb(null, 'eyJ0.eyJpc3Mi.dBjf');
          });
        }
      };
      
      jwt.seal = sinon.spy(jwt.seal);
      
    
      var tokens = new Tokens()
        , token;
      
      tokens.use('application/jwt', jwt);
      tokens._keyring = keyring;
      
      before(function(done) {
        tokens.issue({ beep: 'boop' }, { ttl: 60000 }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keyring.get.callCount).to.equal(1);
        var call = keyring.get.getCall(0);
        expect(call.args[0]).to.be.undefined;
        expect(call.args[1]).to.deep.equal({
          usage: 'encrypt'
        });
      });
      
      it('should seal message', function() {
        expect(jwt.seal.callCount).to.equal(1);
        var call = jwt.seal.getCall(0);
        expect(call.args[0]).to.deep.equal({
          beep: 'boop'
        });
        expect(call.args[1]).to.deep.equal({
          secret: 'keyboardcat'
        });
        expect(call.args[2]).to.deep.equal({
          ttl: 60000
        });
      });
      
      it('should yield token', function() {
        expect(token).to.equal('eyJ0.eyJpc3Mi.dBjf');
      });
    }); // to self with ttl option
    
    describe('to self with type option', function() {
      var keyring = new Object();
      keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' });
    
      var jwt = {
        seal: function(claims, key, cb) {
          process.nextTick(function() {
            return cb(null, 'eyJ0.eyJpc3Mi.dBjf');
          });
        }
      };
      
      var iron = {
        seal: function(claims, key, cb) {
          process.nextTick(function() {
            return cb(null, 'Fe26.2**0cdd60*aOZLCK*g0ilND**05b894*R8yscV');
          });
        }
      };
      
      jwt.seal = sinon.spy(jwt.seal);
      iron.seal = sinon.spy(iron.seal);
      
    
      var tokens = new Tokens()
        , token;
      
      tokens.use('application/jwt', jwt);
      tokens.use('application/fe26.2', iron);
      tokens._keyring = keyring;
      
      before(function(done) {
        tokens.issue({ beep: 'boop' }, { type: 'application/fe26.2' }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keyring.get.callCount).to.equal(1);
        var call = keyring.get.getCall(0);
        expect(call.args[0]).to.be.undefined;
        expect(call.args[1]).to.deep.equal({
          usage: 'encrypt'
        });
      });
      
      it('should seal message', function() {
        expect(iron.seal.callCount).to.equal(1);
        var call = iron.seal.getCall(0);
        expect(call.args[0]).to.deep.equal({
          beep: 'boop'
        });
        expect(call.args[1]).to.deep.equal({
          secret: 'keyboardcat'
        });
      });
      
      it('should yield token', function() {
        expect(token).to.equal('Fe26.2**0cdd60*aOZLCK*g0ilND**05b894*R8yscV');
      });
    }); // to self with type option
    
    describe('to recipient', function() {
      var keyring = new Object();
      keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' });
    
      var jwt = {
        seal: function(claims, key, cb) {
          process.nextTick(function() {
            return cb(null, 'eyJ0.eyJpc3Mi.dBjf');
          });
        }
      };
      
      jwt.seal = sinon.spy(jwt.seal);
      
    
      var tokens = new Tokens()
        , token;
      
      tokens.use('application/jwt', jwt);
      tokens._keyring = keyring;
      
      before(function(done) {
        tokens.issue({ beep: 'boop' }, 'example.com', function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keyring.get.callCount).to.equal(1);
        var call = keyring.get.getCall(0);
        expect(call.args[0]).to.equal('example.com');
        expect(call.args[1]).to.deep.equal({
          usage: 'encrypt'
        });
      });
      
      it('should seal message', function() {
        expect(jwt.seal.callCount).to.equal(1);
        var call = jwt.seal.getCall(0);
        expect(call.args[0]).to.deep.equal({
          beep: 'boop'
        });
        expect(call.args[1]).to.deep.equal({
          secret: 'keyboardcat'
        });
      });
      
      it('should yield token', function() {
        expect(token).to.equal('eyJ0.eyJpc3Mi.dBjf');
      });
    }); // to recipient
    
    describe('to recipient with ttl option', function() {
      var keyring = new Object();
      keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' });
    
      var jwt = {
        seal: function(claims, key, options, cb) {
          process.nextTick(function() {
            return cb(null, 'eyJ0.eyJpc3Mi.dBjf');
          });
        }
      };
      
      jwt.seal = sinon.spy(jwt.seal);
      
    
      var tokens = new Tokens()
        , token;
      
      tokens.use('application/jwt', jwt);
      tokens._keyring = keyring;
      
      before(function(done) {
        tokens.issue({ beep: 'boop' }, 'example.com', { ttl: 60000 }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keyring.get.callCount).to.equal(1);
        var call = keyring.get.getCall(0);
        expect(call.args[0]).to.equal('example.com');
        expect(call.args[1]).to.deep.equal({
          usage: 'encrypt'
        });
      });
      
      it('should seal message', function() {
        expect(jwt.seal.callCount).to.equal(1);
        var call = jwt.seal.getCall(0);
        expect(call.args[0]).to.deep.equal({
          beep: 'boop'
        });
        expect(call.args[1]).to.deep.equal({
          secret: 'keyboardcat'
        });
        expect(call.args[2]).to.deep.equal({
          ttl: 60000
        });
      });
      
      it('should yield token', function() {
        expect(token).to.equal('eyJ0.eyJpc3Mi.dBjf');
      });
    }); // to recipient with ttl option
    
    describe('to recipient with type option', function() {
      var keyring = new Object();
      keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' });
    
      var jwt = {
        seal: function(claims, key, cb) {
          process.nextTick(function() {
            return cb(null, 'eyJ0.eyJpc3Mi.dBjf');
          });
        }
      };
      
      var iron = {
        seal: function(claims, key, cb) {
          process.nextTick(function() {
            return cb(null, 'Fe26.2**0cdd60*aOZLCK*g0ilND**05b894*R8yscV');
          });
        }
      };
      
      jwt.seal = sinon.spy(jwt.seal);
      iron.seal = sinon.spy(iron.seal);
      
    
      var tokens = new Tokens()
        , token;
      
      tokens.use('application/jwt', jwt);
      tokens.use('application/fe26.2', iron);
      tokens._keyring = keyring;
      
      before(function(done) {
        tokens.issue({ beep: 'boop' }, 'example.com', { type: 'application/fe26.2' }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keyring.get.callCount).to.equal(1);
        var call = keyring.get.getCall(0);
        expect(call.args[0]).to.equal('example.com');
        expect(call.args[1]).to.deep.equal({
          usage: 'encrypt'
        });
      });
      
      it('should seal message', function() {
        expect(iron.seal.callCount).to.equal(1);
        var call = iron.seal.getCall(0);
        expect(call.args[0]).to.deep.equal({
          beep: 'boop'
        });
        expect(call.args[1]).to.deep.equal({
          secret: 'keyboardcat'
        });
      });
      
      it('should yield token', function() {
        expect(token).to.equal('Fe26.2**0cdd60*aOZLCK*g0ilND**05b894*R8yscV');
      });
    }); // to recipient with type option
    
    describe('to recipient as object with default options', function() {
      var keyring = new Object();
      keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' });
    
      var jwt = {
        seal: function(claims, key, cb) {
          process.nextTick(function() {
            return cb(null, 'eyJ0.eyJpc3Mi.dBjf');
          });
        }
      };
      
      jwt.seal = sinon.spy(jwt.seal);
      
    
      var tokens = new Tokens()
        , token;
      
      tokens.use('application/jwt', jwt);
      tokens._keyring = keyring;
      
      before(function(done) {
        tokens.issue({ beep: 'boop' }, { id: 's6BhdRkqt3' }, {}, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keyring.get.callCount).to.equal(1);
        var call = keyring.get.getCall(0);
        expect(call.args[0]).to.deep.equal({ id: 's6BhdRkqt3' });
        expect(call.args[1]).to.deep.equal({
          usage: 'encrypt'
        });
      });
      
      it('should seal message', function() {
        expect(jwt.seal.callCount).to.equal(1);
        var call = jwt.seal.getCall(0);
        expect(call.args[0]).to.deep.equal({
          beep: 'boop'
        });
        expect(call.args[1]).to.deep.equal({
          secret: 'keyboardcat'
        });
      });
      
      it('should yield token', function() {
        expect(token).to.equal('eyJ0.eyJpc3Mi.dBjf');
      });
    }); // to recipient as object with default options
    
    describe('to recipient as object with type option', function() {
      var keyring = new Object();
      keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' });
    
      var jwt = {
        seal: function(claims, key, cb) {
          process.nextTick(function() {
            return cb(null, 'eyJ0.eyJpc3Mi.dBjf');
          });
        }
      };
      
      var iron = {
        seal: function(claims, key, cb) {
          process.nextTick(function() {
            return cb(null, 'Fe26.2**0cdd60*aOZLCK*g0ilND**05b894*R8yscV');
          });
        }
      };
      
      jwt.seal = sinon.spy(jwt.seal);
      iron.seal = sinon.spy(iron.seal);
      
    
      var tokens = new Tokens()
        , token;
      
      tokens.use('application/jwt', jwt);
      tokens.use('application/fe26.2', iron);
      tokens._keyring = keyring;
      
      before(function(done) {
        tokens.issue({ beep: 'boop' }, { id: 's6BhdRkqt3' }, { type: 'application/fe26.2' }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keyring.get.callCount).to.equal(1);
        var call = keyring.get.getCall(0);
        expect(call.args[0]).to.deep.equal({
          id: 's6BhdRkqt3'
        });
        expect(call.args[1]).to.deep.equal({
          usage: 'encrypt'
        });
      });
      
      it('should seal message', function() {
        expect(iron.seal.callCount).to.equal(1);
        var call = iron.seal.getCall(0);
        expect(call.args[0]).to.deep.equal({
          beep: 'boop'
        });
        expect(call.args[1]).to.deep.equal({
          secret: 'keyboardcat'
        });
      });
      
      it('should yield token', function() {
        expect(token).to.equal('Fe26.2**0cdd60*aOZLCK*g0ilND**05b894*R8yscV');
      });
    }); // to recipient as object with type option
    
    describe('with dialects', function() {
      
      describe('arity one', function() {
        var keyring = new Object();
        keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' });
    
        var access = {
          encode: function(msg) {
            return {
              bep: msg.beep
            };
          }
        };
        
        access.encode = sinon.spy(access.encode);
        
        var dialects = new Dialects();
        dialects.use('application/jwt', access);
    
        var jwt = {
          seal: function(claims, key, cb) {
            process.nextTick(function() {
              return cb(null, 'eyJ0.eyJpc3Mi.dBjf');
            });
          }
        };
      
        jwt.seal = sinon.spy(jwt.seal);
      
    
        var tokens = new Tokens(dialects)
          , token;
      
        tokens.use('application/jwt', jwt);
        tokens._keyring = keyring;
      
        before(function(done) {
          tokens.issue({ beep: 'boop' }, function(err, t) {
            token = t;
            done(err);
          });
        });
        
        it('should encode message', function() {
          expect(access.encode.callCount).to.equal(1);
          var call = access.encode.getCall(0);
          expect(call.args[0]).to.deep.equal({
            beep: 'boop'
          });
        });
      
        it('should query for key', function() {
          expect(keyring.get.callCount).to.equal(1);
          var call = keyring.get.getCall(0);
          expect(call.args[0]).to.be.undefined;
          expect(call.args[1]).to.deep.equal({
            usage: 'encrypt'
          });
        });
      
        it('should seal message', function() {
          expect(jwt.seal.callCount).to.equal(1);
          var call = jwt.seal.getCall(0);
          expect(call.args[0]).to.deep.equal({
            bep: 'boop'
          });
          expect(call.args[1]).to.deep.equal({
            secret: 'keyboardcat'
          });
        });
      
        it('should yield token', function() {
          expect(token).to.equal('eyJ0.eyJpc3Mi.dBjf');
        });
      }); // arity one
      
      describe('arity two', function() {
        var keyring = new Object();
        keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' });
    
        var access = {
          encode: function(msg, options) {
            return {
              bep: msg.beep
            };
          }
        };
        
        access.encode = sinon.spy(access.encode);
        
        var dialects = new Dialects();
        dialects.use('application/jwt', access);
    
        var jwt = {
          seal: function(claims, key, cb) {
            process.nextTick(function() {
              return cb(null, 'eyJ0.eyJpc3Mi.dBjf');
            });
          }
        };
      
        jwt.seal = sinon.spy(jwt.seal);
      
    
        var tokens = new Tokens(dialects)
          , token;
      
        tokens.use('application/jwt', jwt);
        tokens._keyring = keyring;
      
        before(function(done) {
          tokens.issue({ beep: 'boop' }, function(err, t) {
            token = t;
            done(err);
          });
        });
        
        it('should encode message', function() {
          expect(access.encode.callCount).to.equal(1);
          var call = access.encode.getCall(0);
          expect(call.args[0]).to.deep.equal({
            beep: 'boop'
          });
          expect(call.args[1]).to.deep.equal({});
        });
      
        it('should query for key', function() {
          expect(keyring.get.callCount).to.equal(1);
          var call = keyring.get.getCall(0);
          expect(call.args[0]).to.be.undefined;
          expect(call.args[1]).to.deep.equal({
            usage: 'encrypt'
          });
        });
      
        it('should seal message', function() {
          expect(jwt.seal.callCount).to.equal(1);
          var call = jwt.seal.getCall(0);
          expect(call.args[0]).to.deep.equal({
            bep: 'boop'
          });
          expect(call.args[1]).to.deep.equal({
            secret: 'keyboardcat'
          });
        });
      
        it('should yield token', function() {
          expect(token).to.equal('eyJ0.eyJpc3Mi.dBjf');
        });
      }); // arity two
      
      describe('arity two with options', function() {
        var keyring = new Object();
        keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' });
    
        var access = {
          encode: function(msg, options) {
            return {
              bep: msg.beep,
              exp: 1544645174
            };
          }
        };
        
        access.encode = sinon.spy(access.encode);
        
        var dialects = new Dialects();
        dialects.use('application/jwt', access);
    
        var jwt = {
          seal: function(claims, key, cb) {
            process.nextTick(function() {
              return cb(null, 'eyJ0.eyJpc3Mi.dBjf');
            });
          }
        };
      
        jwt.seal = sinon.spy(jwt.seal);
      
    
        var tokens = new Tokens(dialects)
          , token;
      
        tokens.use('application/jwt', jwt);
        tokens._keyring = keyring;
      
        before(function(done) {
          tokens.issue({ beep: 'boop' }, { ttl: 60000 }, function(err, t) {
            token = t;
            done(err);
          });
        });
        
        it('should encode message', function() {
          expect(access.encode.callCount).to.equal(1);
          var call = access.encode.getCall(0);
          expect(call.args[0]).to.deep.equal({
            beep: 'boop'
          });
          expect(call.args[1]).to.deep.equal({
            ttl: 60000
          });
        });
      
        it('should query for key', function() {
          expect(keyring.get.callCount).to.equal(1);
          var call = keyring.get.getCall(0);
          expect(call.args[0]).to.be.undefined;
          expect(call.args[1]).to.deep.equal({
            usage: 'encrypt'
          });
        });
      
        it('should seal message', function() {
          expect(jwt.seal.callCount).to.equal(1);
          var call = jwt.seal.getCall(0);
          expect(call.args[0]).to.deep.equal({
            bep: 'boop',
            exp: 1544645174
          });
          expect(call.args[1]).to.deep.equal({
            secret: 'keyboardcat'
          });
        });
      
        it('should yield token', function() {
          expect(token).to.equal('eyJ0.eyJpc3Mi.dBjf');
        });
      }); // arity two with options
      
      describe('arity three', function() {
        var keyring = new Object();
        keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' });
    
        var access = {
          encode: function(msg, options, cb) {
            process.nextTick(function() {
              return cb(null, {
                bep: msg.beep
              });
            });
          }
        };
        
        access.encode = sinon.spy(access.encode);
        
        var dialects = new Dialects();
        dialects.use('application/jwt', access);
    
        var jwt = {
          seal: function(claims, key, cb) {
            process.nextTick(function() {
              return cb(null, 'eyJ0.eyJpc3Mi.dBjf');
            });
          }
        };
      
        jwt.seal = sinon.spy(jwt.seal);
      
    
        var tokens = new Tokens(dialects)
          , token;
      
        tokens.use('application/jwt', jwt);
        tokens._keyring = keyring;
      
        before(function(done) {
          tokens.issue({ beep: 'boop' }, function(err, t) {
            token = t;
            done(err);
          });
        });
        
        it('should encode message', function() {
          expect(access.encode.callCount).to.equal(1);
          var call = access.encode.getCall(0);
          expect(call.args[0]).to.deep.equal({
            beep: 'boop'
          });
          expect(call.args[1]).to.deep.equal({});
        });
      
        it('should query for key', function() {
          expect(keyring.get.callCount).to.equal(1);
          var call = keyring.get.getCall(0);
          expect(call.args[0]).to.be.undefined;
          expect(call.args[1]).to.deep.equal({
            usage: 'encrypt'
          });
        });
      
        it('should seal message', function() {
          expect(jwt.seal.callCount).to.equal(1);
          var call = jwt.seal.getCall(0);
          expect(call.args[0]).to.deep.equal({
            bep: 'boop'
          });
          expect(call.args[1]).to.deep.equal({
            secret: 'keyboardcat'
          });
        });
      
        it('should yield token', function() {
          expect(token).to.equal('eyJ0.eyJpc3Mi.dBjf');
        });
      }); // arity three
      
      describe('arity three with options', function() {
        var keyring = new Object();
        keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' });
    
        var access = {
          encode: function(msg, options, cb) {
            process.nextTick(function() {
              return cb(null, {
                bep: msg.beep,
                exp: 1544645174
              });
            });
          }
        };
        
        access.encode = sinon.spy(access.encode);
        
        var dialects = new Dialects();
        dialects.use('application/jwt', access);
    
        var jwt = {
          seal: function(claims, key, cb) {
            process.nextTick(function() {
              return cb(null, 'eyJ0.eyJpc3Mi.dBjf');
            });
          }
        };
      
        jwt.seal = sinon.spy(jwt.seal);
      
    
        var tokens = new Tokens(dialects)
          , token;
      
        tokens.use('application/jwt', jwt);
        tokens._keyring = keyring;
      
        before(function(done) {
          tokens.issue({ beep: 'boop' }, { ttl: 60000 }, function(err, t) {
            token = t;
            done(err);
          });
        });
        
        it('should encode message', function() {
          expect(access.encode.callCount).to.equal(1);
          var call = access.encode.getCall(0);
          expect(call.args[0]).to.deep.equal({
            beep: 'boop'
          });
          expect(call.args[1]).to.deep.equal({
            ttl: 60000
          });
        });
      
        it('should query for key', function() {
          expect(keyring.get.callCount).to.equal(1);
          var call = keyring.get.getCall(0);
          expect(call.args[0]).to.be.undefined;
          expect(call.args[1]).to.deep.equal({
            usage: 'encrypt'
          });
        });
      
        it('should seal message', function() {
          expect(jwt.seal.callCount).to.equal(1);
          var call = jwt.seal.getCall(0);
          expect(call.args[0]).to.deep.equal({
            bep: 'boop',
            exp: 1544645174
          });
          expect(call.args[1]).to.deep.equal({
            secret: 'keyboardcat'
          });
        });
      
        it('should yield token', function() {
          expect(token).to.equal('eyJ0.eyJpc3Mi.dBjf');
        });
      }); // arity three with options
      
      describe('addressing to recipient as object', function() {
        var keyring = new Object();
        keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' });
    
        var access = {
          encode: function(claims) {
            return {
              bep: claims.beep
            };
          },
          
          address: function(recipient) {
            return {
              aud: recipient.id
            }
          }
        };
        
        var dialects = new Dialects();
        dialects.use('application/jwt', access);
    
        var jwt = {
          seal: function(claims, key, cb) {
            process.nextTick(function() {
              return cb(null, 'eyJ0.eyJpc3Mi.dBjf');
            });
          }
        };
      
        jwt.seal = sinon.spy(jwt.seal);
      
    
        var tokens = new Tokens(dialects)
          , token;
      
        tokens.use('application/jwt', jwt);
        tokens._keyring = keyring;
      
        before(function(done) {
          tokens.issue({ beep: 'boop' }, { id: 's6BhdRkqt3' }, {}, function(err, t) {
            token = t;
            done(err);
          });
        });
      
        it('should query for key', function() {
          expect(keyring.get.callCount).to.equal(1);
          var call = keyring.get.getCall(0);
          expect(call.args[0]).to.deep.equal({
            id: 's6BhdRkqt3'
          });
          expect(call.args[1]).to.deep.equal({
            usage: 'encrypt'
          });
        });
      
        it('should seal message', function() {
          expect(jwt.seal.callCount).to.equal(1);
          var call = jwt.seal.getCall(0);
          expect(call.args[0]).to.deep.equal({
            aud: 's6BhdRkqt3',
            bep: 'boop'
          });
          expect(call.args[1]).to.deep.equal({
            secret: 'keyboardcat'
          });
        });
      
        it('should yield token', function() {
          expect(token).to.equal('eyJ0.eyJpc3Mi.dBjf');
        });
      }); // addressing to recipient as object
      
    }); // with dialects
    
  }); // #issue
  
});
