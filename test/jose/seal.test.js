var setup = require('../../lib/jose/seal')
  , fs = require('fs')
  , jose = require('node-jose')
  , jws = require('jws')
  , sinon = require('sinon');


describe('jose/seal', function() {
  
  it('should export generator', function() {
    expect(setup).to.be.a('function');
  });
  
  describe('defaults', function() {
    
    describe('signing to self', function() {
      var object;
      
      var keying = sinon.stub().yields(null, { secret: '12abcdef7890abcdef7890abcdef7890' });
      
      before(function(done) {
        var seal = setup(keying);
        seal({ beep: 'boop' }, { confidential: false }, function(err, o) {
          object = o;
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
      
      it('should generate an object', function() {
        expect(object).to.be.an('object');
        
        expect(Object.keys(object)).to.have.length(3);
        expect(object.protected).to.be.a('string');
        expect(object.payload).to.be.a('string');
        expect(object.signature).to.be.an('string');
        
        var so = jose.parse(object);
        
        expect(so.all).to.have.length(1);
        expect(so.all[0]).to.be.an('object');
        expect(Object.keys(so.all[0])).to.have.length(3);
        expect(so.all[0].typ).to.equal('JOSE+JSON');
        expect(so.all[0].alg).to.equal('HS256');
        expect(so.all[0].cty).to.equal('json');
      });
      
      describe('verifying object', function() {
        var header, protected, claims;
        before(function(done) {
          var jwk = {
            kty: 'oct',
            k: jose.util.base64url.encode('12abcdef7890abcdef7890abcdef7890')
          };
          
          var keystore = jose.JWK.createKeyStore();
          keystore.add(jwk)
            .then(function() {
              return jose.JWS.createVerify(keystore).verify(object);
            })
            .then(function(result) {
              header = result.header;
              protected = result.protected;
              claims = JSON.parse(result.payload.toString());
              done();
            });
        });
        
        it('should have correct header', function() {
          expect(header).to.be.an('object');
          expect(Object.keys(header)).to.have.length(3);
          expect(header.typ).to.equal('JOSE+JSON');
          expect(header.alg).to.equal('HS256');
          expect(header.cty).to.equal('json');
          
          expect(protected).to.deep.equal(['typ', 'cty', 'alg']);
        });
        
        it('should have correct claims', function() {
          expect(claims).to.be.an('object');
          expect(Object.keys(claims)).to.have.length(1);
          expect(claims.beep).to.equal('boop');
        });
      });
    }); // signing to self
    
    describe('signing to recipient using HS256', function() { // SHA-256 HMAC
      var object;
      
      var keying = sinon.stub().yields(null, { secret: 'API-12abcdef7890abcdef7890abcdef', algorithm: 'hmac-sha256' });
      
      before(function(done) {
        var recipients = [ {
          location: 'https://api.example.com/'
        } ];
        
        var seal = setup(keying);
        seal({ beep: 'boop' }, { recipients: recipients, confidential: false }, function(err, o) {
          object = o;
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
      
      it('should generate an object', function() {
        expect(object).to.be.an('object');
        
        expect(Object.keys(object)).to.have.length(3);
        expect(object.protected).to.be.a('string');
        expect(object.payload).to.be.a('string');
        expect(object.signature).to.be.an('string');
        
        var so = jose.parse(object);
        
        expect(so.all).to.have.length(1);
        expect(so.all[0]).to.be.an('object');
        expect(Object.keys(so.all[0])).to.have.length(3);
        expect(so.all[0].typ).to.equal('JOSE+JSON');
        expect(so.all[0].alg).to.equal('HS256');
        expect(so.all[0].cty).to.equal('json');
      });
      
      describe('verifying object', function() {
        var header, protected, claims;
        before(function(done) {
          var jwk = {
            kty: 'oct',
            k: jose.util.base64url.encode('API-12abcdef7890abcdef7890abcdef')
          };
          
          var keystore = jose.JWK.createKeyStore();
          keystore.add(jwk)
            .then(function() {
              return jose.JWS.createVerify(keystore).verify(object);
            })
            .then(function(result) {
              header = result.header;
              protected = result.protected;
              claims = JSON.parse(result.payload.toString());
              done();
            });
        });
        
        it('should have correct header', function() {
          expect(header).to.be.an('object');
          expect(Object.keys(header)).to.have.length(3);
          expect(header.typ).to.equal('JOSE+JSON');
          expect(header.alg).to.equal('HS256');
          expect(header.cty).to.equal('json');
          
          expect(protected).to.deep.equal(['typ', 'cty', 'alg']);
        });
        
        it('should have correct claims', function() {
          expect(claims).to.be.an('object');
          expect(Object.keys(claims)).to.have.length(1);
          expect(claims.beep).to.equal('boop');
        });
      });
    }); // signing to recipient using HS256
    
    describe.skip('signing to recipient using HS512', function() { // SHA-512 HMAC
      var object;
      
      var keying = sinon.stub().yields(null, { secret: '12abcdef7890abcdef7890abcdef789012abcdef7890abcdef7890abcdef7890', algorithm: 'hmac-sha512' });
      
      before(function(done) {
        var recipients = [ {
          location: 'https://api.example.com/'
        } ];
        
        var seal = setup(keying);
        seal({ beep: 'boop' }, { recipients: recipients, confidential: false }, function(err, o) {
          object = o;
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
      
      it('should generate an object', function() {
        expect(object).to.be.an('object');
        
        expect(Object.keys(object)).to.have.length(3);
        expect(object.protected).to.be.a('string');
        expect(object.payload).to.be.a('string');
        expect(object.signature).to.be.an('string');
        
        var so = jose.parse(object);
        
        expect(so.all).to.have.length(1);
        expect(so.all[0]).to.be.an('object');
        expect(Object.keys(so.all[0])).to.have.length(3);
        expect(so.all[0].typ).to.equal('JOSE+JSON');
        expect(so.all[0].alg).to.equal('HS512');
        expect(so.all[0].cty).to.equal('json');
      });
      
      describe('verifying object', function() {
        var header, protected, claims;
        before(function(done) {
          var jwk = {
            kty: 'oct',
            k: jose.util.base64url.encode('12abcdef7890abcdef7890abcdef789012abcdef7890abcdef7890abcdef7890')
          };
          
          var keystore = jose.JWK.createKeyStore();
          keystore.add(jwk)
            .then(function() {
              return jose.JWS.createVerify(keystore).verify(object);
            })
            .then(function(result) {
              header = result.header;
              protected = result.protected;
              claims = JSON.parse(result.payload.toString());
              done();
            });
        });
        
        it('should have correct header', function() {
          expect(header).to.be.an('object');
          expect(Object.keys(header)).to.have.length(3);
          expect(header.typ).to.equal('JOSE+JSON');
          expect(header.alg).to.equal('HS256');
          expect(header.cty).to.equal('json');
          
          expect(protected).to.deep.equal(['typ', 'cty', 'alg']);
        });
        
        it('should have correct claims', function() {
          expect(claims).to.be.an('object');
          expect(Object.keys(claims)).to.have.length(1);
          expect(claims.beep).to.equal('boop');
        });
      });
    }); // signing to recipient using HS512
    
    describe('signing to two recipients using HS256', function() { // SHA-256 HMAC
      var object;
      
      var keying = sinon.spy(function(entity, q, cb){
        switch (entity.location) {
        case 'https://api.example.com/':
          return cb(null, { secret: 'API-12abcdef7890abcdef7890abcdef', algorithm: 'hmac-sha256' });
        case 'https://api.example.net/':
          return cb(null, { secret: 'NET-12abcdef7890abcdef7890abcdef', algorithm: 'hmac-sha256' });
        }
      });
      
      before(function(done) {
        var recipients = [ {
          location: 'https://api.example.com/'
        }, {
          location: 'https://api.example.net/'
        } ];
        
        var seal = setup(keying);
        seal({ beep: 'boop' }, { recipients: recipients, confidential: false }, function(err, o) {
          object = o;
          done(err);
        });
      });
      
      it('should query for key', function() {
        expect(keying.callCount).to.equal(2);
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          location: 'https://api.example.com/'
        });
        expect(call.args[1]).to.deep.equal({
          usage: 'sign',
          algorithms: [ 'hmac-sha256', 'rsa-sha256' ]
        });
        var call = keying.getCall(1);
        expect(call.args[0]).to.deep.equal({
          location: 'https://api.example.net/'
        });
        expect(call.args[1]).to.deep.equal({
          usage: 'sign',
          algorithms: [ 'hmac-sha256', 'rsa-sha256' ]
        });
      });
      
      it('should generate an object', function() {
        expect(object).to.be.an('object');
        
        expect(Object.keys(object)).to.have.length(2);
        expect(object.payload).to.be.a('string');
        expect(object.signatures).to.be.an('array');
        expect(object.signatures).to.have.length(2);
        expect(object.signatures[0]).to.be.an('object');
        expect(Object.keys(object.signatures[0])).to.have.length(2);
        expect(object.signatures[0].protected).to.be.a('string');
        expect(object.signatures[0].signature).to.be.a('string');
        expect(object.signatures[1]).to.be.an('object');
        expect(Object.keys(object.signatures[1])).to.have.length(2);
        expect(object.signatures[1].protected).to.be.a('string');
        expect(object.signatures[1].signature).to.be.a('string');
        
        var so = jose.parse(object);
        
        expect(so.all).to.have.length(2);
        expect(so.all[0]).to.be.an('object');
        expect(Object.keys(so.all[0])).to.have.length(3);
        expect(so.all[0].typ).to.equal('JOSE+JSON');
        expect(so.all[0].alg).to.equal('HS256');
        expect(so.all[0].cty).to.equal('json');
        expect(so.all[1]).to.be.an('object');
        expect(Object.keys(so.all[1])).to.have.length(3);
        expect(so.all[1].typ).to.equal('JOSE+JSON');
        expect(so.all[1].alg).to.equal('HS256');
        expect(so.all[1].cty).to.equal('json');
      });
      
      describe('verifying object by first recipient', function() {
        var header, protected, claims;
        before(function(done) {
          var jwk = {
            kty: 'oct',
            k: jose.util.base64url.encode('API-12abcdef7890abcdef7890abcdef')
          };
          
          var keystore = jose.JWK.createKeyStore();
          keystore.add(jwk)
            .then(function() {
              return jose.JWS.createVerify(keystore).verify(object);
            })
            .then(function(result) {
              header = result.header;
              protected = result.protected;
              claims = JSON.parse(result.payload.toString());
              done();
            })
        });
        
        it('should have correct header', function() {
          expect(header).to.be.an('object');
          expect(Object.keys(header)).to.have.length(3);
          expect(header.typ).to.equal('JOSE+JSON');
          expect(header.alg).to.equal('HS256');
          expect(header.cty).to.equal('json');
          
          expect(protected).to.deep.equal(['typ', 'cty', 'alg']);
        });
        
        it('should have correct claims', function() {
          expect(claims).to.be.an('object');
          expect(Object.keys(claims)).to.have.length(1);
          expect(claims.beep).to.equal('boop');
        });
      });
      
      describe('verifying object by second recipient', function() {
        var header, protected, claims;
        before(function(done) {
          var jwk = {
            kty: 'oct',
            k: jose.util.base64url.encode('NET-12abcdef7890abcdef7890abcdef')
          };
          
          var keystore = jose.JWK.createKeyStore();
          keystore.add(jwk)
            .then(function() {
              return jose.JWS.createVerify(keystore).verify(object);
            })
            .then(function(result) {
              header = result.header;
              protected = result.protected;
              claims = JSON.parse(result.payload.toString());
              done();
            })
        });
        
        it('should have correct header', function() {
          expect(header).to.be.an('object');
          expect(Object.keys(header)).to.have.length(3);
          expect(header.typ).to.equal('JOSE+JSON');
          expect(header.alg).to.equal('HS256');
          expect(header.cty).to.equal('json');
          
          expect(protected).to.deep.equal(['typ', 'cty', 'alg']);
        });
        
        it('should have correct claims', function() {
          expect(claims).to.be.an('object');
          expect(Object.keys(claims)).to.have.length(1);
          expect(claims.beep).to.equal('boop');
        });
      });
    }); // signing to two recipients using HS256
    
    describe('signing to recipient with RS256', function() { // RSA-256
      var object;
      
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
        seal({ beep: 'boop' }, { recipients: recipients, confidential: false }, function(err, o) {
          object = o;
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
      
      it('should generate an object', function() {
        expect(object).to.be.an('object');
        
        expect(Object.keys(object)).to.have.length(3);
        expect(object.protected).to.be.a('string');
        expect(object.payload).to.be.a('string');
        expect(object.signature).to.be.an('string');
        
        var so = jose.parse(object);
        
        expect(so.all).to.have.length(1);
        expect(so.all[0]).to.be.an('object');
        expect(Object.keys(so.all[0])).to.have.length(4);
        expect(so.all[0].typ).to.equal('JOSE+JSON');
        expect(so.all[0].alg).to.equal('RS256');
        expect(so.all[0].kid).to.equal('1');
        expect(so.all[0].cty).to.equal('json');
      });
      
      describe('verifying object', function() {
        var header, protected, claims;
        before(function(done) {
          var keystore = jose.JWK.createKeyStore();
          return jose.JWK.asKey(fs.readFileSync(__dirname + '/../keys/rsa/private-key.pem'), 'pem')
            .then(function(k) {
              var jwk = k.toJSON(true);
              jwk.kid = '1';
              return keystore.add(jwk);
            })
            .then(function() {
              return jose.JWS.createVerify(keystore).verify(object);
            })
            .then(function(result) {
              header = result.header;
              protected = result.protected;
              claims = JSON.parse(result.payload.toString());
              done();
            });
        });
        
        it('should have correct header', function() {
          expect(header).to.be.an('object');
          expect(Object.keys(header)).to.have.length(4);
          expect(header.typ).to.equal('JOSE+JSON');
          expect(header.alg).to.equal('RS256');
          expect(header.kid).to.equal('1');
          expect(header.cty).to.equal('json');
          
          expect(protected).to.deep.equal(['typ', 'cty', 'alg', 'kid']);
        });
        
        it('should have correct claims', function() {
          expect(claims).to.be.an('object');
          expect(Object.keys(claims)).to.have.length(1);
          expect(claims.beep).to.equal('boop');
        });
      });
    }); // signing to recipient with RS256
    
    describe('encrypting to self', function() {
      var object;
      
      var keying = sinon.stub().yields(null, { secret: '12abcdef7890abcdef7890abcdef7890' });
      
      before(function(done) {
        var seal = setup(keying);
        seal({ beep: 'boop' }, function(err, o) {
          object = o;
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
      
      it('should generate an object', function() {
        expect(object).to.be.an('object');
        
        expect(Object.keys(object)).to.have.length(5);
        expect(object.protected).to.be.a('string');
        expect(object.encrypted_key).to.be.a('string');
        expect(object.iv).to.be.a('string');
        expect(object.ciphertext).to.be.a('string');
        expect(object.tag).to.be.a('string');
        
        var so = jose.parse(object);
        
        expect(so.all).to.have.length(1);
        expect(so.all[0]).to.be.an('object');
        expect(Object.keys(so.all[0])).to.have.length(4);
        expect(so.all[0].typ).to.equal('JOSE+JSON');
        expect(so.all[0].alg).to.equal('A256KW');
        expect(so.all[0].enc).to.equal('A128CBC-HS256');
        expect(so.all[0].cty).to.equal('json');
      });
      
      describe('decrypting object', function() {
        var header, protected, claims;
        before(function(done) {
          var jwk = {
            kty: 'oct',
            k: jose.util.base64url.encode('12abcdef7890abcdef7890abcdef7890')
          };
          
          var keystore = jose.JWK.createKeyStore();
          keystore.add(jwk)
            .then(function() {
              return jose.JWE.createDecrypt(keystore).decrypt(object);
            })
            .then(function(result) {
              header = result.header;
              protected = result.protected;
              claims = JSON.parse(result.payload.toString());
              done();
            });
        });
        
        it('should have correct header', function() {
          expect(header).to.be.an('object');
          expect(Object.keys(header)).to.have.length(4);
          expect(header.typ).to.equal('JOSE+JSON');
          expect(header.alg).to.equal('A256KW');
          expect(header.enc).to.equal('A128CBC-HS256');
          expect(header.cty).to.equal('json');
          
          expect(protected).to.deep.equal(['typ', 'cty', 'enc', 'alg']);
        });
        
        it('should have correct claims', function() {
          expect(claims).to.be.an('object');
          expect(Object.keys(claims)).to.have.length(1);
          expect(claims.beep).to.equal('boop');
        });
      });
    }); // encrypting to self
    
    describe('encrypting to recipient using AES-128 in CBC mode with SHA-256 HMAC', function() {
      var object;
      
      var keying = sinon.stub().yields(null, { secret: 'API-12abcdef7890abcdef7890abcdef', algorithm: 'aes128-cbc-hmac-sha256' });
      
      before(function(done) {
        var recipients = [ {
          location: 'https://api.example.com/'
        } ];
        
        var seal = setup(keying);
        seal({ beep: 'boop' }, recipients, function(err, o) {
          object = o;
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
      
      it('should generate an object', function() {
        expect(object).to.be.an('object');
        
        expect(Object.keys(object)).to.have.length(5);
        expect(object.protected).to.be.a('string');
        expect(object.encrypted_key).to.be.a('string');
        expect(object.iv).to.be.a('string');
        expect(object.ciphertext).to.be.a('string');
        expect(object.tag).to.be.a('string');
        
        var so = jose.parse(object);
        
        expect(so.all).to.have.length(1);
        expect(so.all[0]).to.be.an('object');
        expect(Object.keys(so.all[0])).to.have.length(4);
        expect(so.all[0].typ).to.equal('JOSE+JSON');
        expect(so.all[0].alg).to.equal('A256KW');
        expect(so.all[0].enc).to.equal('A128CBC-HS256');
        expect(so.all[0].cty).to.equal('json');
      });
      
      describe('decrypting object', function() {
        var header, protected, claims;
        before(function(done) {
          var jwk = {
            kty: 'oct',
            k: jose.util.base64url.encode('API-12abcdef7890abcdef7890abcdef')
          };
          
          var keystore = jose.JWK.createKeyStore();
          keystore.add(jwk)
            .then(function() {
              return jose.JWE.createDecrypt(keystore).decrypt(object);
            })
            .then(function(result) {
              header = result.header;
              protected = result.protected;
              claims = JSON.parse(result.payload.toString());
              done();
            });
        });
        
        it('should have correct header', function() {
          expect(header).to.be.an('object');
          expect(Object.keys(header)).to.have.length(4);
          expect(header.typ).to.equal('JOSE+JSON');
          expect(header.alg).to.equal('A256KW');
          expect(header.enc).to.equal('A128CBC-HS256');
          expect(header.cty).to.equal('json');
          
          expect(protected).to.deep.equal(['typ', 'cty', 'enc', 'alg']);
        });
        
        it('should have correct claims', function() {
          expect(claims).to.be.an('object');
          expect(Object.keys(claims)).to.have.length(1);
          expect(claims.beep).to.equal('boop');
        });
      });
    }); // encrypting to recipient using AES-128 in CBC mode with SHA-256 HMAC
    
    describe('encrypting to recipient using RSA-OAEP', function() {
      var object;
      
      var keying = sinon.stub().yields(null, {
        id: '1',
        key: fs.readFileSync(__dirname + '/../keys/rsa/cert.pem'),
        algorithm: 'rsa-sha256'
      });
      
      before(function(done) {
        var recipients = [ {
          location: 'https://api.example.com/'
        } ];
        
        var seal = setup(keying);
        seal({ beep: 'boop' }, recipients, function(err, o) {
          object = o;
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
      
      it('should generate an object', function() {
        expect(object).to.be.an('object');
        
        expect(Object.keys(object)).to.have.length(5);
        expect(object.protected).to.be.a('string');
        expect(object.encrypted_key).to.be.a('string');
        expect(object.iv).to.be.a('string');
        expect(object.ciphertext).to.be.a('string');
        expect(object.tag).to.be.a('string');
        
        var so = jose.parse(object);
        
        expect(so.all).to.have.length(1);
        expect(so.all[0]).to.be.an('object');
        expect(Object.keys(so.all[0])).to.have.length(5);
        expect(so.all[0].typ).to.equal('JOSE+JSON');
        expect(so.all[0].alg).to.equal('RSA-OAEP');
        expect(so.all[0].enc).to.equal('A128CBC-HS256');
        expect(so.all[0].kid).to.equal('1');
        expect(so.all[0].cty).to.equal('json');
      });
      
      describe('decrypting object', function() {
        var header, protected, claims;
        before(function(done) {
          var keystore = jose.JWK.createKeyStore();
          return jose.JWK.asKey(fs.readFileSync(__dirname + '/../keys/rsa/private-key.pem'), 'pem')
            .then(function(k) {
              var jwk = k.toJSON(true);
              jwk.kid = '1';
              return keystore.add(jwk);
            })
            .then(function() {
              return jose.JWE.createDecrypt(keystore).decrypt(object);
            })
            .then(function(result) {
              header = result.header;
              protected = result.protected;
              claims = JSON.parse(result.payload.toString());
              done();
            });
        });
        
        it('should have correct header', function() {
          expect(header).to.be.an('object');
          expect(Object.keys(header)).to.have.length(5);
          expect(header.typ).to.equal('JOSE+JSON');
          expect(header.alg).to.equal('RSA-OAEP');
          expect(header.enc).to.equal('A128CBC-HS256');
          expect(header.kid).to.equal('1');
          expect(header.cty).to.equal('json');
          
          expect(protected).to.deep.equal(['typ', 'cty', 'enc', 'alg', 'kid']);
        });
        
        it('should have correct claims', function() {
          expect(claims).to.be.an('object');
          expect(Object.keys(claims)).to.have.length(1);
          expect(claims.beep).to.equal('boop');
        });
      });
    }); // encrypting to recipient using RSA-OAEP
    
  }); // defaults
  
  describe.skip('using defaults', function() {
    var seal, keying;
    
    before(function() {
      keying = sinon.spy(function(q, cb){
        if (!q.recipient) {
          return cb(null, [ {
            id: '1',
            secret: '12abcdef7890abcdef7890abcdef7890',
            algorithm: q.usage == 'sign' ? 'hmac-sha256' : 'aes128-cbc-hmac-sha256'
          } ]);
        }
        
        var recip = q.recipient;
        
        switch (recip.id) {
        case 'https://api.example.com/jws/HS256':
        case 'https://api.example.net/jws/HS256':
          return cb(null, [ {
            secret: recip.secret,
            algorithm: q.usage == 'sign' ? 'hmac-sha256' : 'aes128-cbc-hmac-sha256'
          } ], 'https://as.example.com');
          
        case 'https://api.example.com/sym/256':
        case 'https://api.example.net/sym/256':
          return cb(null, [ {
            secret: recip.secret,
            algorithm: q.usage == 'sign' ? 'hmac-sha256' : 'aes128-cbc-hmac-sha256'
          } ], 'https://as.example.com');
          
        case 'https://api.example.com/asym/256':
          switch (q.usage) {
          case 'sign':
            return cb(null, [ {
              id: '13',
              privateKey: fs.readFileSync(__dirname + '/../keys/rsa/private-key.pem'),
              algorithm: 'rsa-sha256'
            } ]);
          case 'encrypt':
            return cb(null, [ {
              id: '13',
              publicKey: fs.readFileSync(__dirname + '/../keys/rsa/cert.pem'),
              algorithm: 'rsa-sha256'
            } ]);
          }
        }
      });
      
      seal = setup(keying);
    });
    
    describe('encrypting to two recipients, both using AES-128 in CBC mode with SHA-256 HMAC', function() {
      var token;
      before(function(done) {
        var audience = [ {
          id: 'https://api.example.com/sym/256',
          secret: 'API-12abcdef7890abcdef7890abcdef'
        }, {
          id: 'https://api.example.net/sym/256',
          secret: 'NET-12abcdef7890abcdef7890abcdef'
        } ];
        
        seal({ foo: 'bar' }, { audience: audience }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      after(function() {
        keying.reset();
      });
      
      it('should query for keys', function() {
        expect(keying.callCount).to.equal(2);
        
        var call = keying.getCall(0);
        expect(call.args[0]).to.deep.equal({
          recipient: {
            id: 'https://api.example.com/sym/256',
            secret: 'API-12abcdef7890abcdef7890abcdef'
          },
          usage: 'encrypt',
          algorithms: [ 'aes128-cbc-hmac-sha256' ]
        });
        
        var call = keying.getCall(1);
        expect(call.args[0]).to.deep.equal({
          recipient: {
            id: 'https://api.example.net/sym/256',
            secret: 'NET-12abcdef7890abcdef7890abcdef'
          },
          usage: 'encrypt',
          algorithms: [ 'aes128-cbc-hmac-sha256' ]
        });
      });
      
      it('should generate a token', function() {
        expect(token).to.be.an('object');
        expect(Object.keys(token)).to.have.length(5);
        
        expect(token.protected).to.be.a('string');
        expect(token.iv).to.be.a('string');
        expect(token.ciphertext).to.be.a('string');
        expect(token.tag).to.be.a('string');
        expect(token.recipients).to.be.an('array');
        expect(token.recipients).to.have.length(2);
        expect(token.recipients[0]).to.be.an('object');
        expect(token.recipients[0].encrypted_key).to.be.a('string');
        expect(token.recipients[0].header).to.be.an('object');
        expect(token.recipients[0].header).to.deep.equal({ alg: 'A256KW' });
        expect(token.recipients[1]).to.be.an('object');
        expect(token.recipients[1].encrypted_key).to.be.a('string');
        expect(token.recipients[1].header).to.be.an('object');
        expect(token.recipients[1].header).to.deep.equal({ alg: 'A256KW' });
        
        var tkn = jose.parse(token);
        
        expect(tkn.all).to.have.length(2);
        expect(tkn.all[0]).to.be.an('object');
        expect(Object.keys(tkn.all[0])).to.have.length(4);
        expect(tkn.all[0].typ).to.equal('JOSE+JSON');
        expect(tkn.all[0].alg).to.equal('A256KW');
        expect(tkn.all[0].enc).to.equal('A128CBC-HS256');
        expect(tkn.all[0].cty).to.equal('json');
        expect(Object.keys(tkn.all[1])).to.have.length(4);
        expect(tkn.all[1].typ).to.equal('JOSE+JSON');
        expect(tkn.all[1].alg).to.equal('A256KW');
        expect(tkn.all[0].enc).to.equal('A128CBC-HS256');
        expect(tkn.all[1].cty).to.equal('json');
      });
      
      /*
      describe('verifying token', function() {
        var header, protected, claims;
        before(function(done) {
          var jwk = {
            kty: 'oct',
            k: jose.util.base64url.encode('API-12abcdef7890abcdef7890abcdef')
          };
          
          var keystore = jose.JWK.createKeyStore();
          keystore.add(jwk).
            then(function() {
              return jose.JWS.createVerify(keystore).verify(token);
            }).
            then(function(result) {
              header = result.header;
              protected = result.protected;
              claims = JSON.parse(result.payload.toString());
              done();
            });
        });
        
        it('should have correct header', function() {
          expect(header).to.be.an('object');
          expect(Object.keys(header)).to.have.length(3);
          expect(header.typ).to.equal('JOSE+JSON');
          expect(header.alg).to.equal('HS256');
          expect(header.cty).to.equal('json');
          
          expect(protected).to.deep.equal(['typ', 'cty', 'alg']);
        });
        
        it('should have correct claims', function() {
          expect(claims).to.be.an('object');
          expect(Object.keys(claims)).to.have.length(2);
          expect(claims.iss).to.equal('https://as.example.com');
          expect(claims.foo).to.equal('bar');
        });
      });
      */
    }); // encrypting to two recipients, both using AES-128 in CBC mode with SHA-256 HMAC
    
    /*
    describe('encrypting arbitrary claims to audience using RSA-OAEP', function() {
      var token;
      before(function(done) {
        var audience = [ {
          id: 'https://api.example.com/asym/256',
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
            id: 'https://api.example.com/asym/256',
          } ],
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
    }); // encrypting arbitrary claims to audience using RSA-OAEP
    */
    
  }); // using defaults
  
}); // jose/seal
