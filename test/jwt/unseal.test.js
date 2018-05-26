var setup = require('../../lib/jwt/unseal')
  , fs = require('fs')
  , jose = require('node-jose')
  , jws = require('jws')
  , sinon = require('sinon');


describe('jwt/unseal', function() {
  
  it('should export generator', function() {
    expect(setup).to.be.a('function');
  });
  
  describe('defaults', function() {
    
    describe('verifying arbitrary claims to self', function() {
      var claims, conditions;
      
      var keying = sinon.stub().yields(null, { id: '1', secret: '12abcdef7890abcdef7890abcdef7890' });
      
      before(function(done) {
        var audience = [ {
          id: 'https://www.example.com'
        } ];
        
        var token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IjEifQ.eyJmb28iOiJiYXIifQ.pF2mdgldyc9az-iY82Lc90L1EYbX4AUnuPzhT6982KQ';
        
        var unseal = setup(keying);
        unseal(token, {}, function(err, c, co) {
          claims = c;
          conditions = co;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.be.undefined;
        expect(call.args[1]).to.deep.equal({
          id: '1',
          usage: 'verify',
          algorithms: [ 'hmac-sha256' ]
        });
      });
      
      it('should parse token', function() {
        expect(claims).to.deep.equal({
          foo: 'bar',
        });
      });
      
      it('should yield conditions', function() {
        expect(conditions).to.deep.equal({
        });
      });
    }); // verifying arbitrary claims to self
    
  });
  
});
