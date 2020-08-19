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
        expect(token).to.be.a('string');
        
        var st = jws.decode(token);
        
        expect(st.header).to.be.an('object');
        expect(Object.keys(st.header)).to.have.length(2);
        expect(st.header.typ).to.equal('JWT');
        expect(st.header.alg).to.equal('HS256');
        
        expect(st.payload).to.be.an('object');
        expect(Object.keys(st.payload)).to.have.length(1);
        expect(st.payload.beep).to.equal('boop');
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
    
    describe('signing to recipient using HS256', function() { // SHA-256 HMAC
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
        expect(token).to.be.a('string');
        
        var st = jws.decode(token);
        
        expect(st.header).to.be.an('object');
        expect(Object.keys(st.header)).to.have.length(2);
        expect(st.header.typ).to.equal('JWT');
        expect(st.header.alg).to.equal('HS256');
        
        expect(st.payload).to.be.an('object');
        expect(Object.keys(st.payload)).to.have.length(1);
        expect(st.payload.beep).to.equal('boop');
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
    }); // signing to recipient using HS256
    
    describe('signing to recipient with HS512', function() { // SHA-512 HMAC
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
        expect(token).to.be.a('string');
        
        var st = jws.decode(token);
        
        expect(st.header).to.be.an('object');
        expect(Object.keys(st.header)).to.have.length(2);
        expect(st.header.typ).to.equal('JWT');
        expect(st.header.alg).to.equal('HS512');
        
        expect(st.payload).to.be.an('object');
        expect(Object.keys(st.payload)).to.have.length(1);
        expect(st.payload.beep).to.equal('boop');
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
    
    describe('signing to recipient with RS256', function() { // RSA-256
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
        expect(token).to.be.a('string');
        
        var st = jws.decode(token);
        
        expect(st.header).to.be.an('object');
        expect(Object.keys(st.header)).to.have.length(3);
        expect(st.header.typ).to.equal('JWT');
        expect(st.header.alg).to.equal('RS256');
        expect(st.header.kid).to.equal('1');
        
        expect(st.payload).to.be.an('object');
        expect(Object.keys(st.payload)).to.have.length(1);
        expect(st.payload.beep).to.equal('boop');
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
      
      var keying = sinon.stub().yields(null, { secret: '12abcdef7890abcdef7890abcdef7890' });
      
      before(function(done) {
        var seal = setup(keying);
        seal({ beep: 'boop' }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(1);
        var call = keying.getCall(0);
        expect(call.args[0]).to.be.undefined;
        expect(call.args[1]).to.deep.equal({
          usage: 'encrypt',
          algorithms: [ 'aes128-cbc-hmac-sha256' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token).to.be.a('string');
        
        var st = jose.parse(token);
        
        expect(st.header).to.be.an('object');
        expect(Object.keys(st.header)).to.have.length(3);
        expect(st.header.typ).to.equal('JWT');
        expect(st.header.alg).to.equal('A256KW');
        expect(st.header.enc).to.equal('A128CBC-HS256');
      });
      
      describe('decrypting token', function() {
        var claims;
        before(function(done) {
          var jwk = {
            kty: 'oct',
            k: jose.util.base64url.encode('12abcdef7890abcdef7890abcdef7890')
          };
          
          var keystore = jose.JWK.createKeyStore();
          keystore.add(jwk)
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
          expect(claims.beep).to.equal('boop');
        });
      });
    }); // encrypting to self
    
    describe('encrypting to recipient using AES-128 in CBC mode with SHA-256 HMAC', function() {
      var token;
      
      var keying = sinon.stub().yields(null, { secret: 'API-12abcdef7890abcdef7890abcdef', algorithm: 'aes128-cbc-hmac-sha256' });
      
      before(function(done) {
        var recipients = [ {
          location: 'https://api.example.com/'
        } ];
        
        var seal = setup(keying);
        seal({ beep: 'boop' }, recipients, function(err, t) {
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
      
      describe('decrypting token', function() {
        var claims;
        before(function(done) {
          var jwk = {
            kty: 'oct',
            k: jose.util.base64url.encode('API-12abcdef7890abcdef7890abcdef')
          };
          
          var keystore = jose.JWK.createKeyStore();
          keystore.add(jwk)
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
          expect(claims.beep).to.equal('boop');
        });
      });
    }); // encrypting to recipient using AES-128 in CBC mode with SHA-256 HMAC
    
    describe('encrypting to recipient using RSA-OAEP', function() {
      var token;
      
      var keying = sinon.stub().yields(null, {
        id: '1',
        key: fs.readFileSync(__dirname + '/../keys/rsa/cert.pem'),
        algorithm: 'rsa-sha256'
      });
      
      before(function(done) {
        var recipients = [ {
          location: 'https://api.example.com/',
        } ];
        
        var seal = setup(keying);
        seal({ beep: 'boop' }, recipients, function(err, t) {
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
          usage: 'encrypt',
          algorithms: [ 'aes128-cbc-hmac-sha256' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token.length).to.equal(324);
        expect(token.substr(0, 2)).to.equal('ey');
        
        var tkn = jose.parse(token);
        
        expect(tkn.header).to.be.an('object');
        expect(Object.keys(tkn.header)).to.have.length(4);
        expect(tkn.header.typ).to.equal('JWT');
        expect(tkn.header.alg).to.equal('RSA-OAEP');
        expect(tkn.header.enc).to.equal('A128CBC-HS256');
        expect(tkn.header.kid).to.equal('1');
      });
      
      describe('decrypting token', function() {
        var claims;
        before(function(done) {
          var keystore = jose.JWK.createKeyStore();
          return jose.JWK.asKey(fs.readFileSync(__dirname + '/../keys/rsa/private-key.pem'), 'pem')
            .then(function(k) {
              var jwk = k.toJSON(true);
              jwk.kid = '1';
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
          expect(claims.beep).to.equal('boop');
        });
      });
    }); // encrypting to recipient using RSA-OAEP
    
  }); // defaults
  
}); // jwt/seal
