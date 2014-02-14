var sat = require('../../lib/decode/sat')
  , fs = require('fs')
  , jws = require('jws');


describe('decode.sat', function() {
  
  it('should be named sat', function() {
    expect(sat(function(){}).name).to.equal('sat');
  });
  
  describe('decoding a valid SAT with type in JWT header', function() {
    // header = { typ: 'JWT', alg: 'RS256' }
    // body = { iss: 'https://op.example.com/',
    //          sub: 'mailto:bob@example.com',
    //          aud: 'https://rp.example.com/',
    //          exp: 7702588800 }
    var data = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL29wLmV4YW1wbGUuY29tLyIsInN1YiI6Im1haWx0bzpib2JAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwczovL3JwLmV4YW1wbGUuY29tLyIsImV4cCI6NzcwMjU4ODgwMH0.md5WnUAcngphUanJq_BBGlVDPOfLAaIuk9OqzQDxADVaLwKJmmMypVzJDw5g7c8xyZDAGD_txjEoEPFcjP9k9dIG1e3JrBpD_RmLPH2VXxsKRDOd3Q3gppt7Axnn4FKLX1M1mALgXt6lzDqo7rcw2GTHkhtdu-riV8aPq52E3hU';
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
  
  describe('decoding a valid SAT without type in JWT header', function() {
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
  
  describe('decoding an invalid SAT due to missing iss claim', function() {
    var data = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJtYWlsdG86Ym9iQGV4YW1wbGUuY29tIiwiYXVkIjoiaHR0cHM6Ly9ycC5leGFtcGxlLmNvbS8iLCJleHAiOjc3MDI1ODg4MDB9.VrDaygaaE-ycWwEQfEe3SdZ7sgcSbSYd0PQ_Z88UF3l3ycp8cvVNStTHaUD9sxpqJN2iV8lgQ2nfa4Ts3l-1g3SWtDcRlo82P_SrmXRaSkw2bL9cv9iwSF238d5DK1Vdu3RtMxcbrgBzhRJj0UlggErj5c9KjN9qmP2oP2kjUKc';
    var claims, error;
    
    before(function(done) {
      function keying(issuer, done) {
        expect(issuer).to.equal('https://op.example.com/');
        
        return fs.readFile(__dirname + '/../keys/rsa/cert.pem', 'utf8', done);
      }
      var decode = sat({ audience: 'https://rp.example.com/' }, keying);
      
      decode(data, function(err, c) {
        error = err;
        claims = c;
        done();
      });
    });
    
    it('should error', function() {
      expect(error).to.be.an.instanceOf(Error);
      expect(error.message).to.equal('Token missing required claim: iss');
      expect(error.code).to.equal('ENOTVALID');
    });
    
    it('should not decode token', function() {
      expect(claims).to.be.undefined;
    });
  });
  
});
