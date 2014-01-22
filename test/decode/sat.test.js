var sat = require('../../lib/decode/sat')
  , fs = require('fs')
  , jws = require('jws');


describe('decode.sat', function() {
  
  it('should be named sat', function() {
    expect(sat(function(){}).name).to.equal('sat');
  });
  
  describe('decoding an access token', function() {
    // header = { alg: 'RS256' }
    // body = { iss: 'https://op.example.com/',
    //          aud: 'https://rp.example.com/',
    //          exp: 7702588800 }
    var data = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL29wLmV4YW1wbGUuY29tLyIsImF1ZCI6Imh0dHBzOi8vcnAuZXhhbXBsZS5jb20vIiwiZXhwIjo3NzAyNTg4ODAwfQ.OR1DUc8DFeedLOPvWV_6gTyFLYgbwaqDWn6nryoq4Q9phfnC3Hd7W1KGmTzjR6WTFnEiNCfddH_XBirZnkXB29nVOtGAclbEbhA0Q7lpuCZYw0XY6Y3X9_5NhubvsbCVUCaN8qZET1nZGtSsl_1Lpd5NUBCgg36e9QgBbvE8Fow';
    var claims;
    
    before(function(done) {
      function keying(issuer, done) {
        expect(issuer).to.equal('https://op.example.com/');
        
        return fs.readFile(__dirname + '/../keys/rsa/cert.pem', 'utf8', done);
      }
      var decode = sat(keying);
      
      decode(data, function(err, c) {
        if (err) { return done(err); }
        claims = c;
        done();
      });
    });
    
    it('should decode token', function() {
      expect(claims).to.be.an('object');
      expect(Object.keys(claims)).to.have.length(3);
      
      expect(claims.issuer).to.equal('https://op.example.com/');
      expect(claims.audience).to.equal('https://rp.example.com/');
      expect(claims.expiresAt).to.be.an.instanceOf(Date);
      expect(claims.expiresAt.getTime()).to.equal(7702588800000);
    });
  });
  
});
