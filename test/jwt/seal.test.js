var setup = require('../../lib/jwt/seal')
  , fs = require('fs')
  , jose = require('node-jose')
  , jws = require('jws')
  , sinon = require('sinon');


describe('jwt/seal', function() {
  
  it('should export generator', function() {
    expect(setup).to.be.a('function');
  });
  
  describe('defaults', function() {
    
    describe('signing to self', function() {
      var token;
      
      var keying = sinon.stub().yields(null, { secret: '12abcdef7890abcdef7890abcdef7890' });
      
      before(function(done) {
        var seal = setup(keying);
        seal({ beep: 'boop' }, { confidential: false }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.be.undefined;
        expect(call.args[1]).to.deep.equal({
          usage: 'sign',
          algorithms: [ 'hmac-sha256', 'rsa-sha256' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.equal(101);
        expect(token.substr(0, 2)).to.equal('ey');
        
        var tkn = jws.decode(token);
        
        expect(tkn.header).to.be.an('object');
        expect(Object.keys(tkn.header)).to.have.length(2);
        expect(tkn.header.typ).to.equal('JWT');
        expect(tkn.header.alg).to.equal('HS256');
        
        expect(tkn.payload).to.be.an('object');
        expect(Object.keys(tkn.payload)).to.have.length(1);
        expect(tkn.payload.beep).to.equal('boop');
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
    
    describe('signing to recipient with HS256', function() {
      var token;
      
      var keying = sinon.stub().yields(null, { secret: 'API-12abcdef7890abcdef7890abcdef', algorithm: 'hmac-sha256' });
      
      before(function(done) {
        var recipients = [ {
          location: 'https://api.example.com/'
        } ];
        
        var seal = setup(keying);
        seal({ beep: 'boop' }, { recipients: recipients, confidential: false }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          location: 'https://api.example.com/'
        });
        expect(call.args[1]).to.deep.equal({
          usage: 'sign',
          algorithms: [ 'hmac-sha256', 'rsa-sha256' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.equal(101);
        expect(token.substr(0, 2)).to.equal('ey');
        
        var tkn = jws.decode(token);
        
        expect(tkn.header).to.be.an('object');
        expect(Object.keys(tkn.header)).to.have.length(2);
        expect(tkn.header.typ).to.equal('JWT');
        expect(tkn.header.alg).to.equal('HS256');
        
        expect(tkn.payload).to.be.an('object');
        expect(Object.keys(tkn.payload)).to.have.length(1);
        expect(tkn.payload.beep).to.equal('boop');
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
    }); // signing to recipient with HS256
    
    describe('signing to recipient with HS512', function() {
      var token;
      
      var keying = sinon.stub().yields(null, { secret: '12abcdef7890abcdef7890abcdef789012abcdef7890abcdef7890abcdef7890', algorithm: 'hmac-sha512' });
      
      before(function(done) {
        var recipients = [ {
          location: 'https://api.example.com/'
        } ];
        
        var seal = setup(keying);
        seal({ beep: 'boop' }, { recipients: recipients, confidential: false }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          location: 'https://api.example.com/',
        });
        expect(call.args[1]).to.deep.equal({
          usage: 'sign',
          algorithms: [ 'hmac-sha256', 'rsa-sha256' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.equal(144);
        expect(token.substr(0, 2)).to.equal('ey');
        
        var tkn = jws.decode(token);
        
        expect(tkn.header).to.be.an('object');
        expect(Object.keys(tkn.header)).to.have.length(2);
        expect(tkn.header.typ).to.equal('JWT');
        expect(tkn.header.alg).to.equal('HS512');
        
        expect(tkn.payload).to.be.an('object');
        expect(Object.keys(tkn.payload)).to.have.length(1);
        expect(tkn.payload.beep).to.equal('boop');
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
    }); // signing to recipient with HS512
    
    describe('signing to recipient with RS256', function() {
      var token;
      
      var keying = sinon.stub().yields(null, {
        id: '1',
        key: fs.readFileSync(__dirname + '/../keys/rsa/private-key.pem'),
        algorithm: 'rsa-sha256'
      });
      
      before(function(done) {
        var recipients = [ {
          location: 'https://api.example.com/'
        } ];
        
        var seal = setup(keying);
        seal({ beep: 'boop' }, { recipients: recipients, confidential: false }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          location: 'https://api.example.com/'
        });
        expect(call.args[1]).to.deep.equal({
          usage: 'sign',
          algorithms: [ 'hmac-sha256', 'rsa-sha256' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.equal(243);
        expect(token.substr(0, 2)).to.equal('ey');
        
        var tkn = jws.decode(token);
        
        expect(tkn.header).to.be.an('object');
        expect(Object.keys(tkn.header)).to.have.length(3);
        expect(tkn.header.typ).to.equal('JWT');
        expect(tkn.header.kid).to.equal('1');
        expect(tkn.header.alg).to.equal('RS256');
        
        expect(tkn.payload).to.be.an('object');
        expect(Object.keys(tkn.payload)).to.have.length(1);
        expect(tkn.payload.beep).to.equal('boop');
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
    }); // signing to recipient with RS256
    
    describe('encrypting to self', function() {
      var token;
      
      var keying = sinon.stub().yields(null, { id: '1', secret: '12abcdef7890abcdef7890abcdef7890', algorithm: 'aes128-cbc-hmac-sha256' });
      
      before(function(done) {
        var seal = setup(keying);
        seal({ foo: 'bar' }, [ { identifier: 'https://self-issued.me' } ], function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          identifier: 'https://self-issued.me',
        });
        expect(call.args[1]).to.deep.equal({
          usage: 'encrypt',
          algorithms: [ 'aes128-cbc-hmac-sha256' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.equal(246);
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
          expect(Object.keys(claims)).to.have.length(2);
          expect(claims.aud).to.equal('https://self-issued.me');
          expect(claims.foo).to.equal('bar');
        });
      });
    }); // encrypting to self
    
    describe('encrypting to audience using AES-128 in CBC mode with SHA-256 HMAC', function() {
      var token;
      
      var keying = sinon.stub().yields(null, { secret: 'API-12abcdef7890abcdef7890abcdef', algorithm: 'aes128-cbc-hmac-sha256' });
      
      before(function(done) {
        var audience = [ {
          id: 'https://api.example.com/jwe/A256KW/A128CBC-HS256',
          secret: 'API-12abcdef7890abcdef7890abcdef'
        } ];
        
        var seal = setup(keying);
        seal({ foo: 'bar' }, audience, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          id: 'https://api.example.com/jwe/A256KW/A128CBC-HS256',
          secret: 'API-12abcdef7890abcdef7890abcdef'
        });
        expect(call.args[1]).to.deep.equal({
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
          expect(Object.keys(claims)).to.have.length(1);
          expect(claims.foo).to.equal('bar');
        });
      });
    }); // encrypting to audience using AES-128 in CBC mode with SHA-256 HMAC
    
    describe('encrypting to audience using RSA-OAEP', function() {
      var token;
      
      var keying = sinon.stub().yields(null, {
        id: '13',
        publicKey: fs.readFileSync(__dirname + '/../keys/rsa/cert.pem'),
        algorithm: 'rsa-sha256'
      });
      
      before(function(done) {
        var audience = [ {
          id: 'https://api.example.com/jwe/RSA-OAEP/A128CBC-HS256',
        } ];
        
        var seal = setup(keying);
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
        expect(call.args[0]).to.deep.equal({
          id: 'https://api.example.com/jwe/RSA-OAEP/A128CBC-HS256'
        });
        expect(call.args[1]).to.deep.equal({
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
          expect(Object.keys(claims)).to.have.length(1);
          expect(claims.foo).to.equal('bar');
        });
      });
    }); // encrypting to audience using RSA-OAEP
    
  }); // using defaults
  
}); // jwt/seal
