var Sealer = require('../lib/sealer')
  , sinon = require('sinon');


describe('Sealer', function() {
  
  describe('signing to self', function() {
    var seal = function(claims, key, cb) {
      process.nextTick(function() {
        return cb(null, '2YotnFZFEjr1zCsicMWpAA');
      });
    }
    var seal = sinon.spy(seal);
    var keyring = new Object();
    keyring.get = sinon.stub().yields(null, { secret: '12abcdef7890abcdef7890abcdef7890' });
    
    var token;
    
    before(function(done) {
      var sealer = new Sealer({ seal: seal }, null, keyring);
      sealer.seal({ beep: 'boop' }, { confidential: false }, function(err, t) {
        token = t;
        done(err);
      });
    });
    
    it('should query for key', function() {
      expect(keyring.get.callCount).to.equal(1);
      var call = keyring.get.getCall(0);
      expect(call.args[0]).to.be.undefined;
      expect(call.args[1]).to.deep.equal({
        usage: 'sign'
      });
    });
    
    it('should call seal implementation', function() {
      expect(seal.callCount).to.equal(1);
      var call = seal.getCall(0);
      expect(call.args[0]).to.deep.equal({
        beep: 'boop'
      });
      expect(call.args[1]).to.deep.equal({
        secret: '12abcdef7890abcdef7890abcdef7890'
      });
    });
    
    it('should generate a token', function() {
      expect(token).to.be.a('string');
    });
  }); // signing to self
  
});
