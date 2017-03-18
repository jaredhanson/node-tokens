var setup = require('../../lib/jwt/seal')
  , fs = require('fs')
  , jose = require('node-jose')
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
        var recip = q.recipients[0];
        
        switch (recip.id) {
        case 'https://www.example.com':
          return cb(null, [ {
            id: '1',
            secret: '12abcdef7890abcdef7890abcdef7890',
            algorithm: q.usage == 'sign' ? 'hmac-sha256' : 'aes128-cbc-hmac-sha256'
          } ]);
          
        case 'https://api.example.com/sym/256':
          return cb(null, [ {
            secret: recip.secret,
            algorithm: 'hmac-sha256'
          } ]);
          
        case 'https://api.example.com/asym/256':
          return cb(null, [ {
            id: '13',
            privateKey: fs.readFileSync(__dirname + '/../keys/rsa/private-key.pem'),
            algorithm: 'rsa-sha256'
          } ]);
        }
      });
      
      seal = setup(keying);
    });
    
    describe('encrypting arbitrary claims to self', function() {
      var token;
      before(function(done) {
        var audience = [ {
          id: 'https://www.example.com'
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
            id: 'https://www.example.com'
          } ],
          usage: 'encrypt',
          algorithms: [ 'aes128-cbc-hmac-sha256' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.equal(204);
        expect(token.substr(0, 2)).to.equal('ey');
        
        var tkn = jose.parse(token);
        
        expect(tkn.header).to.be.an('object');
        expect(Object.keys(tkn.header)).to.have.length(4);
        expect(tkn.header.typ).to.equal('JWT');
        expect(tkn.header.alg).to.equal('A256KW');
        expect(tkn.header.enc).to.equal('A128CBC-HS256');
        expect(tkn.header.kid).to.equal('1');
      });
      
      describe('verifying token', function() {
        var claims;
        before(function(done) {
          var jwk = {
            kty: 'oct',
            kid: '1',
            k: jose.util.base64url.encode('12abcdef7890abcdef7890abcdef7890')
          };
          
          var keystore = jose.JWK.createKeyStore();
          keystore.add(jwk).
            then(function() {
              return jose.JWE.createDecrypt(keystore).decrypt(token);
            }).
            then(function(result) {
              claims = JSON.parse(result.payload.toString());
              done();
            });
        });
        
        it('should be valid', function() {
          expect(claims).to.be.an('object');
          expect(claims.foo).to.equal('bar');
        });
      });
    }); // encrypting arbitrary claims
    
    describe('signing arbitrary claims to self', function() {
      var token;
      before(function(done) {
        var audience = [ {
          id: 'https://www.example.com'
        } ];
        
        seal({ foo: 'bar' }, { audience: audience, confidential: false }, function(err, t) {
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
            id: 'https://www.example.com'
          } ],
          usage: 'sign',
          algorithms: [ 'hmac-sha256', 'rsa-sha256' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.equal(113);
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
      
      describe('verifying token', function() {
        var valid;
        before(function() {
          valid = jws.verify(token, 'HS256', '12abcdef7890abcdef7890abcdef7890');
        });
        
        it('should be valid', function() {
          expect(valid).to.be.true;
        });
      });
    }); // signing arbitrary claims
    
    describe('signing arbitrary claims to audience using HMAC SHA-256', function() {
      var token;
      before(function(done) {
        var audience = [ {
          id: 'https://api.example.com/sym/256',
          secret: 'API-12abcdef7890abcdef7890abcdef'
        } ];
        
        seal({ foo: 'bar' }, { audience: audience, confidential: false }, function(err, t) {
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
            id: 'https://api.example.com/sym/256',
            secret: 'API-12abcdef7890abcdef7890abcdef'
          } ],
          usage: 'sign',
          algorithms: [ 'hmac-sha256', 'rsa-sha256' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.equal(99);
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
      
      describe('verifying token', function() {
        var valid;
        before(function() {
          valid = jws.verify(token, 'HS256', 'API-12abcdef7890abcdef7890abcdef');
        });
        
        it('should be valid', function() {
          expect(valid).to.be.true;
        });
      });
    }); // signing arbitrary claims to audience using HMAC SHA-256
    
    describe('signing arbitrary claims to audience using RSA-256', function() {
      var token;
      before(function(done) {
        var audience = [ {
          id: 'https://api.example.com/asym/256'
        } ];
        
        seal({ foo: 'bar' }, { audience: audience, confidential: false }, function(err, t) {
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
            id: 'https://api.example.com/asym/256'
          } ],
          usage: 'sign',
          algorithms: [ 'hmac-sha256', 'rsa-sha256' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.equal(242);
        expect(token.substr(0, 2)).to.equal('ey');
        
        var tkn = jws.decode(token);
        
        expect(tkn.header).to.be.an('object');
        expect(Object.keys(tkn.header)).to.have.length(3);
        expect(tkn.header.typ).to.equal('JWT');
        expect(tkn.header.alg).to.equal('RS256');
        expect(tkn.header.kid).to.equal('13');
        
        expect(tkn.payload).to.be.an('object');
        expect(Object.keys(tkn.payload)).to.have.length(1);
        expect(tkn.payload.foo).to.equal('bar');
      });
      
      describe('verifying token', function() {
        var valid;
        before(function() {
          valid = jws.verify(token, 'RS256', fs.readFileSync(__dirname + '/../keys/rsa/cert.pem'));
        });
        
        it('should be valid', function() {
          expect(valid).to.be.true;
        });
      });
    }); // signing arbitrary claims to audience using RSA-256
    
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
