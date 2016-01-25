var sat = require('../../lib/encode/sat')
  , fs = require('fs')
  , jws = require('jws');


describe('encode.sat', function() {
  
  it('should export generator', function() {
    expect(sat).to.be.a('function');
  });
  
  describe('constructed with issuer and key', function() {
    var encode = sat({ issuer: 'https://www.example.com/',
                       key: fs.readFileSync(__dirname + '/../keys/rsa/private-key.pem') });
    
    
    describe('encoding standard claims', function() {
      var claims = { subject: '1234',
                     audience: 'http://www.example.net/',
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
        expect(token.length).to.equal(375);
        var d = jws.decode(token);
        
        expect(d.header).to.be.an('object');
        expect(Object.keys(d.header)).to.have.length(2);
        expect(d.header.typ).to.equal('JWT');
        expect(d.header.alg).to.equal('RS256');
        
        expect(d.payload).to.be.an('object');
        expect(Object.keys(d.payload)).to.have.length(6);
        expect(d.payload.iss).to.equal('https://www.example.com/');
        expect(d.payload.sub).to.equal('1234');
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
  });
  
});
