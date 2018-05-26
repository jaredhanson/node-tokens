var setup = require('../../lib/jwt/unseal')
  , fs = require('fs')
  , jose = require('node-jose')
  , jws = require('jws')
  , sinon = require('sinon');


describe('jwt/unseal', function() {
  
  it('should export generator', function() {
    expect(setup).to.be.a('function');
  });
  
  describe('using defaults', function() {
    var unseal, keying;
    
    before(function() {
      keying = sinon.spy(function(entity, q, cb){
        //var recip = q.recipients[0];
        
        var sender = q.sender || {};
        
        switch (sender.id) {
        case undefined: // self
          if (q.id == '1') {
            return cb(null, {
              id: '1',
              secret: '12abcdef7890abcdef7890abcdef7890',
              algorithm: q.usage == 'verify' ? 'hmac-sha256' : 'aes128-cbc-hmac-sha256'
            });
          }
        };
      });
      
      unseal = setup(keying);
    });
    
    describe('verifying arbitrary claims to self', function() {
      var tkn;
      before(function(done) {
        var audience = [ {
          id: 'https://www.example.com'
        } ];
        
        var token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6IjEifQ.eyJmb28iOiJiYXIifQ.pF2mdgldyc9az-iY82Lc90L1EYbX4AUnuPzhT6982KQ';
        
        unseal(token, {}, function(err, t) {
          tkn = t;
          done(err);
        });
      });
      
      after(function() {
        keying.reset();
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
        //expect(tkn.issuer).to.equal(undefined);
        //expect(tkn.headers).to.deep.equal({
          //issuer: undefined,
          //});
        expect(tkn).to.deep.equal({
          foo: 'bar',
        });
      });
    }); // verifying arbitrary claims to self
    
  });
  
});
