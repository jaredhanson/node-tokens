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
    
    describe('verifying SHA-256 HMAC', function() {
      var claims, conditions;
      
      var keying = sinon.stub().yields(null, { id: '1', secret: '12abcdef7890abcdef7890abcdef7890' });
      
      before(function(done) {
        var token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IjEifQ.eyJmb28iOiJiYXIifQ.pF2mdgldyc9az-iY82Lc90L1EYbX4AUnuPzhT6982KQ';
        
        var unseal = setup(keying);
        unseal(token, function(err, c, co) {
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
      
      it('should yield claims', function() {
        expect(claims).to.deep.equal({
          foo: 'bar',
        });
      });
      
      it('should yield conditions', function() {
        expect(conditions).to.deep.equal({
        });
      });
    }); // verifying SHA-256 HMAC
    
    describe('verifying SHA-256 HMAC with issuer', function() {
      var claims, conditions;
      
      var keying = sinon.stub().yields(null, { secret: 'API-12abcdef7890abcdef7890abcdef' });
      
      before(function(done) {
        var token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.N-fqHy7SUddGTOwJfWqbK4cL4tjFwei_gvZTPwrZoJw';
        
        var unseal = setup(keying);
        unseal(token, { issuer: { identifier: 'https://server.example.com' } }, function(err, c, co) {
          claims = c;
          conditions = co;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({ identifier: 'https://server.example.com' });
        expect(call.args[1]).to.deep.equal({
          id: undefined,
          usage: 'verify',
          algorithms: [ 'hmac-sha256' ]
        });
      });
      
      it('should yield claims', function() {
        expect(claims).to.deep.equal({
          foo: 'bar',
        });
      });
      
      it('should yield conditions', function() {
        expect(conditions).to.deep.equal({
        });
      });
    }); // verifying SHA-256 HMAC with issuer
    
    describe('verifying SHA-512 HMAC with issuer', function() {
      var claims, conditions;
      
      var keying = sinon.stub().yields(null, { secret: '12abcdef7890abcdef7890abcdef789012abcdef7890abcdef7890abcdef7890' });
      
      before(function(done) {
        var token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJmb28iOiJiYXIifQ.C2ByMFhukyOQ1aoUyepRscKZa4w188qdho6-DkhOe8mXS3M5yG1b_yXCw6KrcT_NCEt_1w9MrfM1yQ3lLOeXzQ';
        
        var unseal = setup(keying);
        unseal(token, { issuer: { identifier: 'https://server.example.com' } }, function(err, c, co) {
          claims = c;
          conditions = co;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({ identifier: 'https://server.example.com' });
        expect(call.args[1]).to.deep.equal({
          id: undefined,
          usage: 'verify',
          algorithms: [ 'hmac-sha256' ]
        });
      });
      
      it('should yield claims', function() {
        expect(claims).to.deep.equal({
          foo: 'bar',
        });
      });
      
      it('should yield conditions', function() {
        expect(conditions).to.deep.equal({
        });
      });
    }); // verifying SHA-512 HMAC with issuer
    
  });
  
});
