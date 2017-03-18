var setup = require('../../lib/jose/seal')
  , fs = require('fs')
  , jose = require('node-jose')
  , jws = require('jws')
  , sinon = require('sinon');


describe('jose/seal', function() {
  
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
            algorithm: q.usage == 'sign' ? 'hmac-sha256' : 'aes128-cbc-hmac-sha256'
          } ]);
          
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
      
      it('should generate a token with JSON Serialization', function() {
        expect(token).to.be.an('object');
        expect(Object.keys(token)).to.have.length(5);
        
        expect(token.recipients).to.be.an('array');
        expect(Object.keys(token.recipients)).to.have.length(1);
        expect(token.recipients[0]).to.be.an('object');
        expect(Object.keys(token.recipients[0])).to.have.length(1);
        expect(token.recipients[0].encrypted_key).to.be.a('string');
        expect(token.protected).to.be.a('string');
        expect(token.iv).to.be.a('string');
        expect(token.ciphertext).to.be.a('string');
        expect(token.tag).to.be.a('string');
        
        var tkn = jose.parse(token);
        
        expect(tkn.all[0]).to.be.an('object');
        expect(Object.keys(tkn.all[0])).to.have.length(5);
        expect(tkn.all[0].typ).to.equal('JOSE+JSON');
        expect(tkn.all[0].alg).to.equal('A256KW');
        expect(tkn.all[0].enc).to.equal('A128CBC-HS256');
        expect(tkn.all[0].kid).to.equal('1');
        expect(tkn.all[0].cty).to.equal('json');
      });
      
      /*
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
      */
    }); // encrypting arbitrary claims
    
    /*
    describe('encrypting arbitrary claims to audience using AES-128 in CBC mode with HMAC SHA-256', function() {
      var token;
      before(function(done) {
        var audience = [ {
          id: 'https://api.example.com/sym/256',
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
            id: 'https://api.example.com/sym/256',
            secret: 'API-12abcdef7890abcdef7890abcdef'
          } ],
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
    }); // encrypting arbitrary claims to audience using AES-128 in CBC mode with HMAC SHA-256
    */
    
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
      
      it('should generate with JSON Serialization', function() {
        console.log(token);
        
        expect(token).to.be.an('object');
        expect(Object.keys(token)).to.have.length(2);
        
        expect(token.payload).to.be.a('string');
        expect(token.signatures).to.be.an('array');
        expect(Object.keys(token.signatures)).to.have.length(1);
        expect(token.signatures[0]).to.be.an('object');
        expect(Object.keys(token.signatures[0])).to.have.length(2);
        expect(token.signatures[0].protected).to.be.a('string');
        expect(token.signatures[0].signature).to.be.a('string');
        
        var tkn = jose.parse(token);
        
        expect(tkn.all[0]).to.be.an('object');
        expect(Object.keys(tkn.all[0])).to.have.length(4);
        expect(tkn.all[0].typ).to.equal('JOSE+JSON');
        expect(tkn.all[0].alg).to.equal('HS256');
        expect(tkn.all[0].kid).to.equal('1');
        expect(tkn.all[0].cty).to.equal('json');
      });
      
      /*
      describe('verifying token', function() {
        var valid;
        before(function() {
          valid = jws.verify(token, 'HS256', '12abcdef7890abcdef7890abcdef7890');
        });
        
        it('should be valid', function() {
          expect(valid).to.be.true;
        });
      });
      */
    }); // signing arbitrary claims
    
    /*
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
    */
    
    /*
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
    */
    
  }); // using defaults
  
});
