var Tokens = require('../lib/tokens')
  , sinon = require('sinon');


describe('Tokens', function() {
  
  describe.only('#issue', function() {
  
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
    
  }); // #issue
  
});
