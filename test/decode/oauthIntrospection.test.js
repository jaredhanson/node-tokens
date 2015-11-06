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
      /*
      expect(Object.keys(claims)).to.have.length(4);
      
      expect(claims.issuer).to.equal('https://op.example.com/');
      expect(claims.subject).to.equal('mailto:bob@example.com');
      expect(claims.audience).to.be.an('array');
      expect(claims.audience[0]).to.equal('https://rp.example.com/');
      expect(claims.expiresAt).to.be.an.instanceOf(Date);
      expect(claims.expiresAt.getTime()).to.equal(7702588800000);
      */
    });
  });
  
});
