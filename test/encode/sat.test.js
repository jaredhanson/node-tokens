var sat = require('../../lib/encode/sat')
  , fs = require('fs')
  , jws = require('jws');


describe('encode.sat', function() {
  
  it('should be named sat', function() {
    expect(sat().name).to.equal('sat');
  });
  
  describe('default algorithm', function() {
    
    var encode = sat({ issuer: 'https://www.example.com/',
                       key: fs.readFileSync(__dirname + '/../keys/rsa/private-key.pem') });
    
    
    describe('encoding info', function() {
      var info = { x: 'foo' };
      var token = encode(info);
      
      it('should encode correctly', function() {
        expect(token.length).to.equal(277);
        var d = jws.decode(token);
        
        expect(d.header).to.be.an('object');
        expect(Object.keys(d.header)).to.have.length(2);
        expect(d.header.typ).to.equal('JWT');
        expect(d.header.alg).to.equal('rs256');
        
        expect(d.payload).to.be.an('object');
        expect(Object.keys(d.payload)).to.have.length(2);
        expect(d.payload.iss).to.equal('https://www.example.com/');
      });
    });
    
  });
  
});
