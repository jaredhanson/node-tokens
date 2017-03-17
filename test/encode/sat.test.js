var setup = require('../../lib/jwt/seal')
  , fs = require('fs')
  , jws = require('jws')
  , sinon = require('sinon');


describe('seal', function() {
  
  it('should export generator', function() {
    expect(setup).to.be.a('function');
  });
  
  describe('using defaults', function() {
    var seal, keying;
    
    before(function() {
      keying = sinon.spy(function(q, cb){
        if (q.recipients) {
          var recipient = q.recipients[0];
          if (recipient.secret && q.algorithms.indexOf('hmac-sha256') !== -1) {
            return cb(null, [ {
              secret: recipient.secret,
              algorithm: 'hmac-sha256'
            } ]);
          } else {
            return cb(null, [ {
              id: 'rsa',
              privateKey: fs.readFileSync(__dirname + '/../keys/rsa/private-key.pem'),
              algorithm: 'rsa-sha256'
            } ]);
          }
        } else {
          return cb(null, [ {
            id: '1',
            secret: '12abcdef7890abcdef7890abcdef7890',
            algorithm: 'hmac-sha256'
          } ]);
        }
      });
      
      seal = setup(keying);
    });
    
    describe('encrypting arbitrary claims', function() {
      var token;
      before(function(done) {
        seal({ foo: 'bar' }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      after(function() {
        keying.reset();
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          recipients: undefined,
          usage: 'sign',
          algorithms: [ 'hmac-sha256' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.be.above(0);
        expect(token.substr(0, 2)).to.equal('ey');
        
        var tkn = jws.decode(token);
        
        expect(tkn.header).to.be.an('object');
        expect(Object.keys(tkn.header)).to.have.length(3);
        expect(tkn.header.typ).to.equal('JWT');
        expect(tkn.header.alg).to.equal('HS256');
        expect(tkn.header.kid).to.equal('1');
        
        expect(tkn.payload).to.be.an('object');
        expect(Object.keys(tkn.payload)).to.have.length(1);
        expect(tkn.payload.foo).to.equal('bar');
      });
      
      describe('verifying claims', function() {
        var valid;
        before(function() {
          valid = jws.verify(token, 'HS256', '12abcdef7890abcdef7890abcdef7890');
        });
        
        it('should be valid', function() {
          expect(valid).to.be.true;
        });
      });
    }); // encrypting arbitrary claims
    
    describe('encrypting arbitrary claims to audience using shared key for HMAC SHA256', function() {
      var token;
      before(function(done) {
        var audience = [ {
          id: 'https://api.example.com/',
          secret: 'API-12abcdef7890abcdef7890abcdef'
        } ];
        
        seal({ foo: 'bar' }, { audience: audience }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      after(function() {
        keying.reset();
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          recipients: [ {
            id: 'https://api.example.com/',
            secret: 'API-12abcdef7890abcdef7890abcdef'
          } ],
          usage: 'sign',
          algorithms: [ 'hmac-sha256' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.be.above(0);
        expect(token.substr(0, 2)).to.equal('ey');
        
        var tkn = jws.decode(token);
        
        expect(tkn.header).to.be.an('object');
        expect(Object.keys(tkn.header)).to.have.length(2);
        expect(tkn.header.typ).to.equal('JWT');
        expect(tkn.header.alg).to.equal('HS256');
        
        expect(tkn.payload).to.be.an('object');
        expect(Object.keys(tkn.payload)).to.have.length(1);
        expect(tkn.payload.foo).to.equal('bar');
      });
      
      describe('verifying claims', function() {
        var valid;
        before(function() {
          valid = jws.verify(token, 'HS256', 'API-12abcdef7890abcdef7890abcdef');
        });
        
        it('should be valid', function() {
          expect(valid).to.be.true;
        });
      });
    }); // encrypting arbitrary claims to audience using shared key for HMAC SHA256
    
    describe('encrypting arbitrary claims to audience using private key for RSA-256', function() {
      var token;
      before(function(done) {
        var audience = [ {
          id: 'https://api.example.com/'
        } ];
        
        seal({ foo: 'bar' }, { audience: audience }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      after(function() {
        keying.reset();
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          recipients: [ {
            id: 'https://api.example.com/'
          } ],
          usage: 'sign',
          algorithms: [ 'hmac-sha256' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.be.above(0);
        expect(token.substr(0, 2)).to.equal('ey');
        
        var tkn = jws.decode(token);
        
        expect(tkn.header).to.be.an('object');
        expect(Object.keys(tkn.header)).to.have.length(3);
        expect(tkn.header.typ).to.equal('JWT');
        expect(tkn.header.alg).to.equal('RS256');
        expect(tkn.header.kid).to.equal('rsa');
        
        expect(tkn.payload).to.be.an('object');
        expect(Object.keys(tkn.payload)).to.have.length(1);
        expect(tkn.payload.foo).to.equal('bar');
      });
      
      describe('verifying claims', function() {
        var valid;
        before(function() {
          valid = jws.verify(token, 'RS256', fs.readFileSync(__dirname + '/../keys/rsa/cert.pem'));
        });
        
        it('should be valid', function() {
          expect(valid).to.be.true;
        });
      });
    }); // encrypting arbitrary claims to audience using private key for RSA-256
    
  }); // using defaults
  
  
  
  describe.skip('constructed with issuer and key', function() {
    var encode = setup({ issuer: 'https://www.example.com/',
                       key: fs.readFileSync(__dirname + '/../keys/rsa/private-key.pem') });
    
    
    describe('encoding standard claims', function() {
      var claims = { id: '11-22-33',
                     subject: '1234',
                     audience: 'http://www.example.net/',
                     authorizedPresenter: 'abcd',
                     scope: 'foo',
                     expiresAt: new Date(1390309288) };
                   
      var token;
      before(function(done){
        encode(claims, function(err, t){
          token = t;
          done(err);
        });
      });
      
      it('should encode claims', function() {
        expect(token.length).to.equal(415);
        var d = jws.decode(token);
        
        expect(d.header).to.be.an('object');
        expect(Object.keys(d.header)).to.have.length(2);
        expect(d.header.typ).to.equal('JWT');
        expect(d.header.alg).to.equal('RS256');
        
        expect(d.payload).to.be.an('object');
        expect(Object.keys(d.payload)).to.have.length(8);
        expect(d.payload.jti).to.equal('11-22-33');
        expect(d.payload.iss).to.equal('https://www.example.com/');
        expect(d.payload.sub).to.equal('1234');
        expect(d.payload.azp).to.equal('abcd');
        expect(d.payload.scope).to.equal('foo');
        expect(d.payload.aud).to.equal('http://www.example.net/');
        expect(d.payload.iat).to.be.within(Math.floor((Date.now() - 2) / 1000), Math.floor(Date.now() / 1000));
        expect(d.payload.exp).to.equal(1390309);
      });
      
      it('should have verifiable signature', function() {
        var ok = jws.verify(token, 'RS256', fs.readFileSync(__dirname + '/../keys/rsa/cert.pem') );
        expect(ok).to.be.true;
      });
    });
    
    describe.skip('encoding standard claims, with multiple scopes', function() {
      var claims = { id: '11-22-33',
                     subject: '1234',
                     audience: 'http://www.example.net/',
                     authorizedPresenter: 'abcd',
                     scope: ['foo', 'bar'],
                     expiresAt: new Date(1390309288) };
                   
      var token;
      before(function(done){
        encode(claims, function(err, t){
          token = t;
          done(err);
        });
      });
      
      it('should encode claims', function() {
        expect(token.length).to.equal(420);
        var d = jws.decode(token);
        
        expect(d.header).to.be.an('object');
        expect(Object.keys(d.header)).to.have.length(2);
        expect(d.header.typ).to.equal('JWT');
        expect(d.header.alg).to.equal('RS256');
        
        expect(d.payload).to.be.an('object');
        expect(Object.keys(d.payload)).to.have.length(8);
        expect(d.payload.jti).to.equal('11-22-33');
        expect(d.payload.iss).to.equal('https://www.example.com/');
        expect(d.payload.sub).to.equal('1234');
        expect(d.payload.azp).to.equal('abcd');
        expect(d.payload.scope).to.equal('foo bar');
        expect(d.payload.aud).to.equal('http://www.example.net/');
        expect(d.payload.iat).to.be.within(Math.floor((Date.now() - 2) / 1000), Math.floor(Date.now() / 1000));
        expect(d.payload.exp).to.equal(1390309);
      });
      
      it('should have verifiable signature', function() {
        var ok = jws.verify(token, 'RS256', fs.readFileSync(__dirname + '/../keys/rsa/cert.pem') );
        expect(ok).to.be.true;
      });
    });
    
    describe.skip('encoding standard claims, without scope', function() {
      var claims = { id: '11-22-33',
                     subject: '1234',
                     audience: 'http://www.example.net/',
                     authorizedPresenter: 'abcd',
                     expiresAt: new Date(1390309288) };
                   
      var token;
      before(function(done){
        encode(claims, function(err, t){
          token = t;
          done(err);
        });
      });
      
      it('should encode claims', function() {
        expect(token.length).to.equal(396);
        var d = jws.decode(token);
        
        expect(d.header).to.be.an('object');
        expect(Object.keys(d.header)).to.have.length(2);
        expect(d.header.typ).to.equal('JWT');
        expect(d.header.alg).to.equal('RS256');
        
        expect(d.payload).to.be.an('object');
        expect(Object.keys(d.payload)).to.have.length(7);
        expect(d.payload.jti).to.equal('11-22-33');
        expect(d.payload.iss).to.equal('https://www.example.com/');
        expect(d.payload.sub).to.equal('1234');
        expect(d.payload.azp).to.equal('abcd');
        expect(d.payload.aud).to.equal('http://www.example.net/');
        expect(d.payload.iat).to.be.within(Math.floor((Date.now() - 2) / 1000), Math.floor(Date.now() / 1000));
        expect(d.payload.exp).to.equal(1390309);
      });
      
      it('should have verifiable signature', function() {
        var ok = jws.verify(token, 'RS256', fs.readFileSync(__dirname + '/../keys/rsa/cert.pem') );
        expect(ok).to.be.true;
      });
    });
  });
  
  
  
});
