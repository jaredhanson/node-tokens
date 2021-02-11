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
        expect(call.args[2]).to.deep.equal({});
      });
      
      it('should yield token', function() {
        expect(token).to.equal('eyJ0.eyJpc3Mi.dBjf');
      });
    }); // to recipient as object with default options
    
    describe('to recipient as object with ttl option', function() {
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
        tokens.issue({ beep: 'boop' }, { id: 's6BhdRkqt3' }, { ttl: 60000 }, function(err, t) {
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
        expect(call.args[2]).to.deep.equal({
          ttl: 60000
        });
      });
      
      it('should yield token', function() {
        expect(token).to.equal('eyJ0.eyJpc3Mi.dBjf');
      });
    }); // to recipient as object with ttl option
    
    describe('to recipient as object with type option', function() {
      var keyring = new Object();
      keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' });
    
      var jwt = {
        seal: function(claims, key, options, cb) {
          process.nextTick(function() {
            return cb(null, 'eyJ0.eyJpc3Mi.dBjf');
          });
        }
      };
      
      var iron = {
        seal: function(claims, key, options, cb) {
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
        expect(call.args[2]).to.deep.equal({
          type: 'application/fe26.2'
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
              scp: msg.scope
            };
          }
        };
        
        access.encode = sinon.spy(access.encode);
        
        var dialects = new Dialects();
        dialects.use('application/at+jwt', access);
    
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
          tokens.issue({ scope: 'profile' }, { dialect: 'application/at+jwt' }, function(err, t) {
            token = t;
            done(err);
          });
        });
        
        it('should encode message', function() {
          expect(access.encode.callCount).to.equal(1);
          var call = access.encode.getCall(0);
          expect(call.args[0]).to.deep.equal({
            scope: 'profile'
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
            scp: 'profile'
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
              scp: msg.scope
            };
          }
        };
        
        access.encode = sinon.spy(access.encode);
        
        var dialects = new Dialects();
        dialects.use('application/at+jwt', access);
    
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
          tokens.issue({ scope: 'profile' }, { dialect: 'application/at+jwt' }, function(err, t) {
            token = t;
            done(err);
          });
        });
        
        it('should encode message', function() {
          expect(access.encode.callCount).to.equal(1);
          var call = access.encode.getCall(0);
          expect(call.args[0]).to.deep.equal({
            scope: 'profile'
          });
          expect(call.args[1]).to.deep.equal({
            dialect: 'application/at+jwt'
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
            scp: 'profile'
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
              scp: msg.scope
            };
          }
        };
        
        access.encode = sinon.spy(access.encode);
        
        var dialects = new Dialects();
        dialects.use('application/at+jwt', access);
    
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
          tokens.issue({ scope: 'profile' }, { dialect: 'application/at+jwt', ttl: 60000 }, function(err, t) {
            token = t;
            done(err);
          });
        });
        
        it('should encode message', function() {
          expect(access.encode.callCount).to.equal(1);
          var call = access.encode.getCall(0);
          expect(call.args[0]).to.deep.equal({
            scope: 'profile'
          });
          expect(call.args[1]).to.deep.equal({
            dialect: 'application/at+jwt',
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
            scp: 'profile'
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
                scp: msg.scope
              });
            });
          }
        };
        
        access.encode = sinon.spy(access.encode);
        
        var dialects = new Dialects();
        dialects.use('application/at+jwt', access);
    
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
          tokens.issue({ scope: 'profile' }, { dialect: 'application/at+jwt' }, function(err, t) {
            token = t;
            done(err);
          });
        });
        
        it('should encode message', function() {
          expect(access.encode.callCount).to.equal(1);
          var call = access.encode.getCall(0);
          expect(call.args[0]).to.deep.equal({
            scope: 'profile'
          });
          expect(call.args[1]).to.deep.equal({
            dialect: 'application/at+jwt'
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
            scp: 'profile'
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
                scp: msg.scope
              });
            });
          }
        };
        
        access.encode = sinon.spy(access.encode);
        
        var dialects = new Dialects();
        dialects.use('application/at+jwt', access);
    
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
          tokens.issue({ scope: 'profile' }, { dialect: 'application/at+jwt', ttl: 60000 }, function(err, t) {
            token = t;
            done(err);
          });
        });
        
        it('should encode message', function() {
          expect(access.encode.callCount).to.equal(1);
          var call = access.encode.getCall(0);
          expect(call.args[0]).to.deep.equal({
            scope: 'profile'
          });
          expect(call.args[1]).to.deep.equal({
            dialect: 'application/at+jwt',
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
            scp: 'profile'
          });
          expect(call.args[1]).to.deep.equal({
            secret: 'keyboardcat'
          });
        });
      
        it('should yield token', function() {
          expect(token).to.equal('eyJ0.eyJpc3Mi.dBjf');
        });
      }); // arity three with options
      
    }); // with dialects
      
    describe('with type dialects', function() {
      
      describe('addressing to recipient', function() {
        var keyring = new Object();
        keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' });
    
        var base = {
          address: function(recipient) {
            return {
              aud: recipient
            }
          }
        }
    
        var access = {
          encode: function(msg) {
            return {
              scp: msg.scope
            };
          }
        };
        
        base.address = sinon.spy(base.address);
        access.encode = sinon.spy(access.encode);
        
        var dialects = new Dialects();
        dialects.use('application/jwt', base);
        dialects.use('application/at+jwt', access);
    
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
          tokens.issue({ scope: 'profile' }, 'example.com', { dialect: 'application/at+jwt'}, function(err, t) {
            token = t;
            done(err);
          });
        });
        
        it('should encode message', function() {
          expect(access.encode.callCount).to.equal(1);
          var call = access.encode.getCall(0);
          expect(call.args[0]).to.deep.equal({
            scope: 'profile'
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
        
        it('should address message', function() {
          expect(base.address.callCount).to.equal(1);
          var call = base.address.getCall(0);
          expect(call.args[0]).to.equal('example.com')
        });
      
        it('should seal message', function() {
          expect(jwt.seal.callCount).to.equal(1);
          var call = jwt.seal.getCall(0);
          expect(call.args[0]).to.deep.equal({
            aud: 'example.com',
            scp: 'profile'
          });
          expect(call.args[1]).to.deep.equal({
            secret: 'keyboardcat'
          });
        });
      
        it('should yield token', function() {
          expect(token).to.equal('eyJ0.eyJpc3Mi.dBjf');
        });
      }); // addressing to recipient
      
      describe('addressing to recipient as object', function() {
        var keyring = new Object();
        keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' });
    
        var base = {
          address: function(recipient) {
            return {
              aud: recipient.id
            }
          }
        };
    
        var access = {
          encode: function(msg) {
            return {
              scp: msg.scope
            };
          }
        };
        
        base.address = sinon.spy(base.address);
        access.encode = sinon.spy(access.encode);
        
        var dialects = new Dialects();
        dialects.use('application/jwt', base);
        dialects.use('application/at+jwt', access);
    
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
          tokens.issue({ scope: 'profile' }, { id: 's6BhdRkqt3' }, { dialect: 'application/at+jwt' }, function(err, t) {
            token = t;
            done(err);
          });
        });
        
        it('should encode message', function() {
          expect(access.encode.callCount).to.equal(1);
          var call = access.encode.getCall(0);
          expect(call.args[0]).to.deep.equal({
            scope: 'profile'
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
        
        it('should address message', function() {
          expect(base.address.callCount).to.equal(1);
          var call = base.address.getCall(0);
          expect(call.args[0]).to.deep.equal({ id: 's6BhdRkqt3' })
        });
      
        it('should seal message', function() {
          expect(jwt.seal.callCount).to.equal(1);
          var call = jwt.seal.getCall(0);
          expect(call.args[0]).to.deep.equal({
            aud: 's6BhdRkqt3',
            scp: 'profile'
          });
          expect(call.args[1]).to.deep.equal({
            secret: 'keyboardcat'
          });
        });
      
        it('should yield token', function() {
          expect(token).to.equal('eyJ0.eyJpc3Mi.dBjf');
        });
      }); // addressing to recipient as object
      
      describe('addressing from sender', function() {
        var keyring = new Object();
        keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' }, 'https://authorization-server.example.com/');
    
        var base = {
          address: function(recipient, sender) {
            return {
              iss: sender,
              aud: recipient
            }
          }
        };
    
        var access = {
          encode: function(msg) {
            return {
              scp: msg.scope
            };
          },
        };
        
        base.address = sinon.spy(base.address);
        access.encode = sinon.spy(access.encode);
        
        var dialects = new Dialects();
        dialects.use('application/jwt', base);
        dialects.use('application/at+jwt', access);
    
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
          tokens.issue({ scope: 'profile' }, 'https://rs.example.com/', { dialect: 'application/at+jwt' }, function(err, t) {
            token = t;
            done(err);
          });
        });
        
        it('should encode message', function() {
          expect(access.encode.callCount).to.equal(1);
          var call = access.encode.getCall(0);
          expect(call.args[0]).to.deep.equal({
            scope: 'profile'
          });
        });
      
        it('should query for key', function() {
          expect(keyring.get.callCount).to.equal(1);
          var call = keyring.get.getCall(0);
          expect(call.args[0]).to.equal('https://rs.example.com/')
          expect(call.args[1]).to.deep.equal({
            usage: 'encrypt'
          });
        });
        
        it('should address message', function() {
          expect(base.address.callCount).to.equal(1);
          var call = base.address.getCall(0);
          expect(call.args[0]).to.equal('https://rs.example.com/');
          expect(call.args[1]).to.equal('https://authorization-server.example.com/');
        });
      
        it('should seal message', function() {
          expect(jwt.seal.callCount).to.equal(1);
          var call = jwt.seal.getCall(0);
          expect(call.args[0]).to.deep.equal({
            iss: 'https://authorization-server.example.com/',
            aud: 'https://rs.example.com/',
            scp: 'profile'
          });
          expect(call.args[1]).to.deep.equal({
            secret: 'keyboardcat'
          });
        });
      
        it('should yield token', function() {
          expect(token).to.equal('eyJ0.eyJpc3Mi.dBjf');
        });
      }); // addressing from sender
      
      describe('addressing from sender as object', function() {
        var keyring = new Object();
        keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' }, { id: 'https://authorization-server.example.com/' });
    
        var base = {
          address: function(recipient, sender) {
            return {
              iss: sender.id,
              aud: recipient.id
            }
          }
        };
    
        var access = {
          encode: function(msg) {
            return {
              scp: msg.scope
            };
          }
        };
        
        base.address = sinon.spy(base.address);
        access.encode = sinon.spy(access.encode);
        
        var dialects = new Dialects();
        dialects.use('application/jwt', base);
        dialects.use('application/at+jwt', access);
    
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
          tokens.issue({ scope: 'profile' }, { id: 'https://rs.example.com/' }, { dialect: 'application/at+jwt' }, function(err, t) {
            token = t;
            done(err);
          });
        });
        
        it('should encode message', function() {
          expect(access.encode.callCount).to.equal(1);
          var call = access.encode.getCall(0);
          expect(call.args[0]).to.deep.equal({
            scope: 'profile'
          });
        });
      
        it('should query for key', function() {
          expect(keyring.get.callCount).to.equal(1);
          var call = keyring.get.getCall(0);
          expect(call.args[0]).to.deep.equal({
            id: 'https://rs.example.com/'
          });
          expect(call.args[1]).to.deep.equal({
            usage: 'encrypt'
          });
        });
        
        it('should address message', function() {
          expect(base.address.callCount).to.equal(1);
          var call = base.address.getCall(0);
          expect(call.args[0]).to.deep.equal({ id: 'https://rs.example.com/' });
          expect(call.args[1]).to.deep.equal({ id: 'https://authorization-server.example.com/' });
        });
      
        it('should seal message', function() {
          expect(jwt.seal.callCount).to.equal(1);
          var call = jwt.seal.getCall(0);
          expect(call.args[0]).to.deep.equal({
            iss: 'https://authorization-server.example.com/',
            aud: 'https://rs.example.com/',
            scp: 'profile'
          });
          expect(call.args[1]).to.deep.equal({
            secret: 'keyboardcat'
          });
        });
      
        it('should yield token', function() {
          expect(token).to.equal('eyJ0.eyJpc3Mi.dBjf');
        });
      }); // addressing from sender as object
      
      describe('addressing with options', function() {
        var keyring = new Object();
        keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' }, { hostname: 'authorization-server.example.com' });
    
        var base = {
          address: function(recipient, sender, options) {
            return {
              iss: sender.hostname,
              aud: recipient.hostname,
              identifier_type: options.identifierType
            }
          }
        };
    
        var access = {
          encode: function(msg) {
            return {
              scp: msg.scope
            };
          }
        };
        
        base.address = sinon.spy(base.address);
        access.encode = sinon.spy(access.encode);
        
        var dialects = new Dialects();
        dialects.use('application/jwt', base);
        dialects.use('application/at+jwt', access);
    
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
          tokens.issue({ scope: 'profile' }, { hostname: 'rs.example.com' }, { dialect: 'application/at+jwt', identifierType: 'hostname' }, function(err, t) {
            token = t;
            done(err);
          });
        });
        
        it('should encode message', function() {
          expect(access.encode.callCount).to.equal(1);
          var call = access.encode.getCall(0);
          expect(call.args[0]).to.deep.equal({
            scope: 'profile'
          });
        });
      
        it('should query for key', function() {
          expect(keyring.get.callCount).to.equal(1);
          var call = keyring.get.getCall(0);
          expect(call.args[0]).to.deep.equal({
            hostname: 'rs.example.com'
          });
          expect(call.args[1]).to.deep.equal({
            usage: 'encrypt'
          });
        });
        
        it('should address message', function() {
          expect(base.address.callCount).to.equal(1);
          var call = base.address.getCall(0);
          expect(call.args[0]).to.deep.equal({ hostname: 'rs.example.com' });
          expect(call.args[1]).to.deep.equal({ hostname: 'authorization-server.example.com' });
          expect(call.args[2]).to.deep.equal({
            dialect: 'application/at+jwt',
            identifierType: 'hostname'
          });
        });
      
        it('should seal message', function() {
          expect(jwt.seal.callCount).to.equal(1);
          var call = jwt.seal.getCall(0);
          expect(call.args[0]).to.deep.equal({
            iss: 'authorization-server.example.com',
            aud: 'rs.example.com',
            scp: 'profile',
            identifier_type: 'hostname'
          });
          expect(call.args[1]).to.deep.equal({
            secret: 'keyboardcat'
          });
        });
      
        it('should yield token', function() {
          expect(token).to.equal('eyJ0.eyJpc3Mi.dBjf');
        });
      }); // addressing with options
      
      describe('addressing into header', function() {
        var keyring = new Object();
        keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' }, { id: 'https://authorization-server.example.com/' });
    
        var base = {
          address: function(recipient, sender, options, cb) {
            process.nextTick(function() {
              return cb(null, null, {
                iss: sender.id,
                aud: recipient.id
              })
            });
          }
        };
    
        var access = {
          encode: function(msg) {
            return {
              scp: msg.scope
            };
          }
        };
        
        base.address = sinon.spy(base.address);
        access.encode = sinon.spy(access.encode);
        
        var dialects = new Dialects();
        dialects.use('application/jwt', base);
        dialects.use('application/at+jwt', access);
    
        var jwt = {
          seal: function(claims, header, key, options, cb) {
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
          tokens.issue({ scope: 'profile' }, { id: 'https://rs.example.com/' }, { dialect: 'application/at+jwt' }, function(err, t) {
            token = t;
            done(err);
          });
        });
        
        it('should encode message', function() {
          expect(access.encode.callCount).to.equal(1);
          var call = access.encode.getCall(0);
          expect(call.args[0]).to.deep.equal({
            scope: 'profile'
          });
        });
      
        it('should query for key', function() {
          expect(keyring.get.callCount).to.equal(1);
          var call = keyring.get.getCall(0);
          expect(call.args[0]).to.deep.equal({
            id: 'https://rs.example.com/'
          });
          expect(call.args[1]).to.deep.equal({
            usage: 'encrypt'
          });
        });
        
        it('should address message', function() {
          expect(base.address.callCount).to.equal(1);
          var call = base.address.getCall(0);
          expect(call.args[0]).to.deep.equal({ id: 'https://rs.example.com/' });
          expect(call.args[1]).to.deep.equal({ id: 'https://authorization-server.example.com/' });
          expect(call.args[2]).to.deep.equal({
            dialect: 'application/at+jwt'
          });
        });
      
        it('should seal message', function() {
          expect(jwt.seal.callCount).to.equal(1);
          var call = jwt.seal.getCall(0);
          expect(call.args[0]).to.deep.equal({
            scp: 'profile'
          });
          expect(call.args[1]).to.deep.equal({
            iss: 'https://authorization-server.example.com/',
            aud: 'https://rs.example.com/',
          });
          expect(call.args[2]).to.deep.equal({
            secret: 'keyboardcat'
          });
          expect(call.args[3]).to.deep.equal({
            dialect: 'application/at+jwt'
          });
        });
      
        it('should yield token', function() {
          expect(token).to.equal('eyJ0.eyJpc3Mi.dBjf');
        });
      }); // addressing into header
      
      describe('encoding options', function() {
        var keyring = new Object();
        keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' }, { id: 'https://authorization-server.example.com/' });
    
        var base = {
          encode: function(msg, options) {
            return {
              exp: 1544645174
            }
          },
          
          address: function(recipient, sender) {
            return {
              iss: sender.id,
              aud: recipient.id
            }
          }
        };
    
        var access = {
          encode: function(msg) {
            return {
              scp: msg.scope
            };
          }
        };
        
        base.encode = sinon.spy(base.encode);
        base.address = sinon.spy(base.address);
        access.encode = sinon.spy(access.encode);
        
        var dialects = new Dialects();
        dialects.use('application/jwt', base);
        dialects.use('application/at+jwt', access);
    
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
          tokens.issue({ scope: 'profile' }, { id: 'https://rs.example.com/' }, { dialect: 'application/at+jwt', ttl: 60000 }, function(err, t) {
            token = t;
            done(err);
          });
        });
        
        it('should encode message', function() {
          expect(access.encode.callCount).to.equal(1);
          var call = access.encode.getCall(0);
          expect(call.args[0]).to.deep.equal({
            scope: 'profile'
          });
        });
        
        it('should encode type', function() {
          expect(base.encode.callCount).to.equal(1);
          var call = base.encode.getCall(0);
          expect(call.args[0]).to.be.null;
          expect(call.args[1]).to.deep.equal({
            dialect: 'application/at+jwt',
            ttl: 60000
          });
        });
      
        it('should query for key', function() {
          expect(keyring.get.callCount).to.equal(1);
          var call = keyring.get.getCall(0);
          expect(call.args[0]).to.deep.equal({
            id: 'https://rs.example.com/'
          });
          expect(call.args[1]).to.deep.equal({
            usage: 'encrypt'
          });
        });
        
        it('should address message', function() {
          expect(base.address.callCount).to.equal(1);
          var call = base.address.getCall(0);
          expect(call.args[0]).to.deep.equal({ id: 'https://rs.example.com/' });
          expect(call.args[1]).to.deep.equal({ id: 'https://authorization-server.example.com/' });
        });
      
        it('should seal message', function() {
          expect(jwt.seal.callCount).to.equal(1);
          var call = jwt.seal.getCall(0);
          expect(call.args[0]).to.deep.equal({
            iss: 'https://authorization-server.example.com/',
            aud: 'https://rs.example.com/',
            scp: 'profile',
            exp: 1544645174
          });
          expect(call.args[1]).to.deep.equal({
            secret: 'keyboardcat'
          });
        });
      
        it('should yield token', function() {
          expect(token).to.equal('eyJ0.eyJpc3Mi.dBjf');
        });
      }); // encoding options
      
    }); // with type dialects
    
  }); // #issue
  
});
