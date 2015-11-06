var $require = require('proxyquire');
var oauthIntrospection = require('../../lib/decode/oauthIntrospection');


describe('decode.oauthIntrospection', function() {
  
  it('should be named oauthIntrospection', function() {
    expect(oauthIntrospection('http://www.example.com/introspect').name).to.equal('oauthIntrospection');
  });
  
  describe('introspecting a token', function() {
    var requestStub = {
      post: function(url, options, cb) {
        expect(url).to.equal('http://www.example.com/introspect');
        expect(options.form.token).to.equal('AT-keyboard-cat');
        
        process.nextTick(function() {
          cb(null, { statusCode: 200 },
'{\
"active": true,\
"client_id": "l238j323ds-23ij4",\
"username": "jdoe",\
"scope": "read write dolphin",\
"sub": "Z5O3upPC88QrAjx00dis",\
"aud": "https://protected.example.net/resource",\
"iss": "https://server.example.com/",\
"exp": 1419356238,\
"iat": 1419350238,\
"extension_field": "twenty-seven"\
}'
          )});
      }
    }
    
    var introspect = $require('../../lib/decode/oauthIntrospection', {
      'request': requestStub
    })('http://www.example.com/introspect');
    
    
    var claims;
    
    before(function(done) {
      introspect('AT-keyboard-cat', function(err, c) {
        if (err) { return done(err); }
        claims = c;
        done();
      });
    });
    
    it('should introspect token', function() {
      expect(claims).to.be.an('object');
      expect(Object.keys(claims)).to.have.length(11);
      
      expect(claims.issuer).to.equal('https://server.example.com/');
      expect(claims.subject).to.equal('Z5O3upPC88QrAjx00dis');
      expect(claims.username).to.equal('jdoe');
      expect(claims.audience).to.be.an('array');
      expect(claims.audience[0]).to.equal('https://protected.example.net/resource');
      expect(claims.authorizedParty).to.equal('l238j323ds-23ij4');
      expect(claims.authorizedPresenter).to.equal('l238j323ds-23ij4');
      expect(claims.scope).to.be.an('array');
      expect(claims.scope[0]).to.equal('read');
      expect(claims.scope[1]).to.equal('write');
      expect(claims.scope[2]).to.equal('dolphin');
      expect(claims.issuedAt).to.be.an.instanceOf(Date);
      expect(claims.issuedAt.getTime()).to.equal(1419350238000);
      expect(claims.expiresAt).to.be.an.instanceOf(Date);
      expect(claims.expiresAt.getTime()).to.equal(1419356238000);
      expect(claims.notBefore).to.equal(undefined);
      expect(claims.id).to.equal(undefined);
      expect(claims.tokenType).to.equal(undefined);
    });
  });
  
  describe('introspecting a token with additional claims', function() {
    var requestStub = {
      post: function(url, options, cb) {
        expect(url).to.equal('http://www.example.com/introspect');
        expect(options.form.token).to.equal('AT-keyboard-cat');
        
        process.nextTick(function() {
          cb(null, { statusCode: 200 },
'{\
"active": true,\
"client_id": "l238j323ds-23ij4",\
"username": "jdoe",\
"scope": "read write dolphin",\
"sub": "Z5O3upPC88QrAjx00dis",\
"aud": "https://protected.example.net/resource",\
"iss": "https://server.example.com/",\
"exp": 1419356238,\
"iat": 1419350238,\
"nbf": 1419351238,\
"jti": "RT-1111-2222",\
"token_type": "refresh_token",\
"extension_field": "twenty-seven"\
}'
          )});
      }
    }
    
    var introspect = $require('../../lib/decode/oauthIntrospection', {
      'request': requestStub
    })('http://www.example.com/introspect');
    
    
    var claims;
    
    before(function(done) {
      introspect('AT-keyboard-cat', function(err, c) {
        if (err) { return done(err); }
        claims = c;
        done();
      });
    });
    
    it('should introspect token', function() {
      expect(claims).to.be.an('object');
      expect(Object.keys(claims)).to.have.length(12);
      
      expect(claims.issuer).to.equal('https://server.example.com/');
      expect(claims.subject).to.equal('Z5O3upPC88QrAjx00dis');
      expect(claims.username).to.equal('jdoe');
      expect(claims.audience).to.be.an('array');
      expect(claims.audience[0]).to.equal('https://protected.example.net/resource');
      expect(claims.authorizedParty).to.equal('l238j323ds-23ij4');
      expect(claims.authorizedPresenter).to.equal('l238j323ds-23ij4');
      expect(claims.scope).to.be.an('array');
      expect(claims.scope[0]).to.equal('read');
      expect(claims.scope[1]).to.equal('write');
      expect(claims.scope[2]).to.equal('dolphin');
      expect(claims.issuedAt).to.be.an.instanceOf(Date);
      expect(claims.issuedAt.getTime()).to.equal(1419350238000);
      expect(claims.expiresAt).to.be.an.instanceOf(Date);
      expect(claims.expiresAt.getTime()).to.equal(1419356238000);
      expect(claims.notBefore).to.be.an.instanceOf(Date);
      expect(claims.notBefore.getTime()).to.equal(1419351238000);
      expect(claims.id).to.equal('RT-1111-2222');
      expect(claims.tokenType).to.equal('refresh_token');
    });
  });
  
  describe('introspecting a token with list of audiences', function() {
    var requestStub = {
      post: function(url, options, cb) {
        expect(url).to.equal('http://www.example.com/introspect');
        expect(options.form.token).to.equal('AT-keyboard-cat');
        
        process.nextTick(function() {
          cb(null, { statusCode: 200 },
'{\
"active": true,\
"client_id": "l238j323ds-23ij4",\
"username": "jdoe",\
"scope": "read write dolphin",\
"sub": "Z5O3upPC88QrAjx00dis",\
"aud": [ "https://protected.example.net/resource", "https://protected.example.net/resource2" ],\
"iss": "https://server.example.com/",\
"exp": 1419356238,\
"iat": 1419350238,\
"extension_field": "twenty-seven"\
}'
          )});
      }
    }
    
    var introspect = $require('../../lib/decode/oauthIntrospection', {
      'request': requestStub
    })('http://www.example.com/introspect');
    
    
    var claims;
    
    before(function(done) {
      introspect('AT-keyboard-cat', function(err, c) {
        if (err) { return done(err); }
        claims = c;
        done();
      });
    });
    
    it('should introspect token', function() {
      expect(claims).to.be.an('object');
      expect(Object.keys(claims)).to.have.length(11);
      
      expect(claims.issuer).to.equal('https://server.example.com/');
      expect(claims.subject).to.equal('Z5O3upPC88QrAjx00dis');
      expect(claims.username).to.equal('jdoe');
      expect(claims.audience).to.be.an('array');
      expect(claims.audience[0]).to.equal('https://protected.example.net/resource');
      expect(claims.audience[1]).to.equal('https://protected.example.net/resource2');
      expect(claims.authorizedParty).to.equal('l238j323ds-23ij4');
      expect(claims.authorizedPresenter).to.equal('l238j323ds-23ij4');
      expect(claims.scope).to.be.an('array');
      expect(claims.scope[0]).to.equal('read');
      expect(claims.scope[1]).to.equal('write');
      expect(claims.scope[2]).to.equal('dolphin');
      expect(claims.issuedAt).to.be.an.instanceOf(Date);
      expect(claims.issuedAt.getTime()).to.equal(1419350238000);
      expect(claims.expiresAt).to.be.an.instanceOf(Date);
      expect(claims.expiresAt.getTime()).to.equal(1419356238000);
      expect(claims.notBefore).to.equal(undefined);
      expect(claims.id).to.equal(undefined);
      expect(claims.tokenType).to.equal(undefined);
    });
  });
  
  describe('introspecting a token without scope', function() {
    var requestStub = {
      post: function(url, options, cb) {
        expect(url).to.equal('http://www.example.com/introspect');
        expect(options.form.token).to.equal('AT-keyboard-cat');
        
        process.nextTick(function() {
          cb(null, { statusCode: 200 },
'{\
"active": true,\
"client_id": "l238j323ds-23ij4",\
"username": "jdoe",\
"sub": "Z5O3upPC88QrAjx00dis",\
"aud": "https://protected.example.net/resource",\
"iss": "https://server.example.com/",\
"exp": 1419356238,\
"iat": 1419350238,\
"extension_field": "twenty-seven"\
}'
          )});
      }
    }
    
    var introspect = $require('../../lib/decode/oauthIntrospection', {
      'request': requestStub
    })('http://www.example.com/introspect');
    
    
    var claims;
    
    before(function(done) {
      introspect('AT-keyboard-cat', function(err, c) {
        if (err) { return done(err); }
        claims = c;
        done();
      });
    });
    
    it('should introspect token', function() {
      expect(claims).to.be.an('object');
      expect(Object.keys(claims)).to.have.length(10);
      
      expect(claims.issuer).to.equal('https://server.example.com/');
      expect(claims.subject).to.equal('Z5O3upPC88QrAjx00dis');
      expect(claims.username).to.equal('jdoe');
      expect(claims.audience).to.be.an('array');
      expect(claims.audience[0]).to.equal('https://protected.example.net/resource');
      expect(claims.authorizedParty).to.equal('l238j323ds-23ij4');
      expect(claims.authorizedPresenter).to.equal('l238j323ds-23ij4');
      expect(claims.scope).to.equal(undefined);
      expect(claims.issuedAt).to.be.an.instanceOf(Date);
      expect(claims.issuedAt.getTime()).to.equal(1419350238000);
      expect(claims.expiresAt).to.be.an.instanceOf(Date);
      expect(claims.expiresAt.getTime()).to.equal(1419356238000);
      expect(claims.notBefore).to.equal(undefined);
      expect(claims.id).to.equal(undefined);
      expect(claims.tokenType).to.equal(undefined);
    });
  });
  
});
