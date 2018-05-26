var setup = require('../../lib/jwt/seal')
  , fs = require('fs')
  , jose = require('node-jose')
  , jws = require('jws')
  , sinon = require('sinon');


describe('jwt/seal', function() {
  
  it('should export generator', function() {
    expect(setup).to.be.a('function');
  });
  
  describe('using defaults', function() {
    var seal, keying;
    
    before(function() {
      keying = sinon.spy(function(entity, q, cb){
        if (!q.recipient) {
          return cb(null, {
            id: '1',
            secret: '12abcdef7890abcdef7890abcdef7890',
            algorithm: q.usage == 'sign' ? 'hmac-sha256' : 'aes128-cbc-hmac-sha256'
          });
        }
        
        var recip = q.recipient;
        
        switch (recip.id) {
        case 'https://api.example.com/jwe/A256KW/A128CBC-HS256':
          return cb(null, {
            secret: recip.secret,
            algorithm: 'aes128-cbc-hmac-sha256'
          });
          
        case 'https://api.example.com/jwe/RSA-OAEP/A128CBC-HS256':
          return cb(null, {
            id: '13',
            publicKey: fs.readFileSync(__dirname + '/../keys/rsa/cert.pem'),
            algorithm: 'rsa-sha256'
          });
          
        case 'https://api.example.com/jws/HS256':
          return cb(null, {
            secret: recip.secret,
            algorithm: 'hmac-sha256'
          });
          
        case 'https://api.example.com/jws/HS512':
          return cb(null, {
            secret: recip.secret,
            algorithm: 'hmac-sha512'
          });
          
        case 'https://api.example.com/jws/RS256':
          return cb(null, {
            id: '13',
            privateKey: fs.readFileSync(__dirname + '/../keys/rsa/private-key.pem'),
            algorithm: 'rsa-sha256'
          });
        }
      });
      
      seal = setup(keying);
    });
    
    describe('signing to self', function() {
      var token;
      
      before(function(done) {
        seal({ foo: 'bar' }, null, { confidential: false }, function(err, t) {
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
        expect(call.args[1]).to.deep.equal({
          recipient: undefined,
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
    }); // signing to self
    
    describe('signing to audience using SHA-256 HMAC', function() {
      var token;
      before(function(done) {
        var audience = [ {
          id: 'https://api.example.com/jws/HS256',
          secret: 'API-12abcdef7890abcdef7890abcdef'
        } ];
        
        seal({ foo: 'bar' }, audience, { confidential: false }, function(err, t) {
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
        expect(call.args[1]).to.deep.equal({
          recipient: {
            id: 'https://api.example.com/jws/HS256',
            secret: 'API-12abcdef7890abcdef7890abcdef'
          },
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
    }); // signing to audience using SHA-256 HMAC
    
    describe('encrypting to self', function() {
      var token;
      before(function(done) {
        var audience = [ {
          id: 'https://www.example.com'
        } ];
        
        seal({ foo: 'bar' }, null, function(err, t) {
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
        expect(call.args[1]).to.deep.equal({
          recipient: undefined,
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
    }); // encrypting to self
    
    describe('encrypting to audience using AES-128 in CBC mode with SHA-256 HMAC', function() {
      var token;
      before(function(done) {
        var audience = [ {
          id: 'https://api.example.com/jwe/A256KW/A128CBC-HS256',
          secret: 'API-12abcdef7890abcdef7890abcdef'
        } ];
        
        seal({ foo: 'bar' }, audience, function(err, t) {
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
        expect(call.args[1]).to.deep.equal({
          recipient: {
            id: 'https://api.example.com/jwe/A256KW/A128CBC-HS256',
            secret: 'API-12abcdef7890abcdef7890abcdef'
          },
          usage: 'encrypt',
          algorithms: [ 'aes128-cbc-hmac-sha256' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.equal(191);
        expect(token.substr(0, 2)).to.equal('ey');
        
        var tkn = jose.parse(token);
        
        expect(tkn.header).to.be.an('object');
        expect(Object.keys(tkn.header)).to.have.length(3);
        expect(tkn.header.typ).to.equal('JWT');
        expect(tkn.header.alg).to.equal('A256KW');
        expect(tkn.header.enc).to.equal('A128CBC-HS256');
      });
      
      describe('verifying token', function() {
        var claims;
        before(function(done) {
          var jwk = {
            kty: 'oct',
            k: jose.util.base64url.encode('API-12abcdef7890abcdef7890abcdef')
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
    }); // encrypting to audience using AES-128 in CBC mode with SHA-256 HMAC
    
    describe('encrypting to audience using RSA-OAEP', function() {
      var token;
      before(function(done) {
        var audience = [ {
          id: 'https://api.example.com/jwe/RSA-OAEP/A128CBC-HS256',
        } ];
        
        seal({ foo: 'bar' }, audience, function(err, t) {
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
        expect(call.args[1]).to.deep.equal({
          recipient: {
            id: 'https://api.example.com/jwe/RSA-OAEP/A128CBC-HS256',
          },
          usage: 'encrypt',
          algorithms: [ 'aes128-cbc-hmac-sha256' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.equal(325);
        expect(token.substr(0, 2)).to.equal('ey');
        
        var tkn = jose.parse(token);
        
        expect(tkn.header).to.be.an('object');
        expect(Object.keys(tkn.header)).to.have.length(4);
        expect(tkn.header.typ).to.equal('JWT');
        expect(tkn.header.alg).to.equal('RSA-OAEP');
        expect(tkn.header.enc).to.equal('A128CBC-HS256');
        expect(tkn.header.kid).to.equal('13');
      });
      
      describe('verifying token', function() {
        var claims;
        before(function(done) {
          var keystore = jose.JWK.createKeyStore();
          return jose.JWK.asKey(fs.readFileSync(__dirname + '/../keys/rsa/private-key.pem'), 'pem')
            .then(function(k) {
              var jwk = k.toJSON(true);
              jwk.kid = '13';
              return keystore.add(jwk);
            })
            .then(function() {
              return jose.JWE.createDecrypt(keystore).decrypt(token);
            })
            .then(function(result) {
              claims = JSON.parse(result.payload.toString());
              done();
            });
        });
        
        it('should be valid', function() {
          expect(claims).to.be.an('object');
          expect(claims.foo).to.equal('bar');
        });
      });
    }); // encrypting to audience using RSA-OAEP
    
    describe('signing to audience using SHA-512 HMAC', function() {
      var token;
      before(function(done) {
        var audience = [ {
          id: 'https://api.example.com/jws/HS512',
          secret: '12abcdef7890abcdef7890abcdef789012abcdef7890abcdef7890abcdef7890'
        } ];
        
        seal({ foo: 'bar' }, audience, { confidential: false }, function(err, t) {
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
        expect(call.args[1]).to.deep.equal({
          recipient: {
            id: 'https://api.example.com/jws/HS512',
            secret: '12abcdef7890abcdef7890abcdef789012abcdef7890abcdef7890abcdef7890'
          },
          usage: 'sign',
          algorithms: [ 'hmac-sha256', 'rsa-sha256' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.equal(142);
        expect(token.substr(0, 2)).to.equal('ey');
        
        var tkn = jws.decode(token);
        
        expect(tkn.header).to.be.an('object');
        expect(Object.keys(tkn.header)).to.have.length(2);
        expect(tkn.header.typ).to.equal('JWT');
        expect(tkn.header.alg).to.equal('HS512');
        
        expect(tkn.payload).to.be.an('object');
        expect(Object.keys(tkn.payload)).to.have.length(1);
        expect(tkn.payload.foo).to.equal('bar');
      });
      
      describe('verifying token', function() {
        var valid;
        before(function() {
          valid = jws.verify(token, 'HS512', '12abcdef7890abcdef7890abcdef789012abcdef7890abcdef7890abcdef7890');
        });
        
        it('should be valid', function() {
          expect(valid).to.be.true;
        });
      });
    }); // signing to audience using SHA-512 HMAC
    
    describe('signing to audience using RSA-256', function() {
      var token;
      before(function(done) {
        var audience = [ {
          id: 'https://api.example.com/jws/RS256'
        } ];
        
        seal({ foo: 'bar' }, audience, { confidential: false }, function(err, t) {
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
        expect(call.args[1]).to.deep.equal({
          recipient: {
            id: 'https://api.example.com/jws/RS256'
          },
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
    }); // signing to audience using RSA-256
    
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
  
  
  
}); // jwt/seal
