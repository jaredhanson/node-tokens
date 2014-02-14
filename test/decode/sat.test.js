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
    //          sub: 'mailto:bob@example.com',
    //          aud: 'https://rp.example.com/',
    //          exp: 7702588800 }
    var data = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL29wLmV4YW1wbGUuY29tLyIsInN1YiI6Im1haWx0bzpib2JAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwczovL3JwLmV4YW1wbGUuY29tLyIsImV4cCI6NzcwMjU4ODgwMH0.ZwLZxuaTnxM74q6QO3JRNuruviw1rZDTETNyPNH7EJ-KOnmEWeVNJhhkncrgNIJO0cbDakW2XVUWeiviYtXQMV0Yyp78uCXM6WB5b7w2i_3Z77rOic2YMnDr0qYBG-hvPdHZ05W_WkOMhEbWZZadWjkdVnbJ2ZzjdHdMStFxcA0';
    var claims;
    
    before(function(done) {
      function keying(issuer, done) {
        expect(issuer).to.equal('https://op.example.com/');
        
        return fs.readFile(__dirname + '/../keys/rsa/cert.pem', 'utf8', done);
      }
      var decode = sat({ audience: 'https://rp.example.com/' }, keying);
      
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
