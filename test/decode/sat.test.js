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
  
  describe('decoding a valid SAT that contains an azp claim', function() {
    // header = { alg: 'RS256' }
    // body = { iss: 'https://op.example.com/',
    //          sub: 'mailto:bob@example.com',
    //          aud: 'https://rp.example.com/',
    //          exp: 7702588800,
    //          azp: 'https://client.example.net/' }
    var data = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL29wLmV4YW1wbGUuY29tLyIsInN1YiI6Im1haWx0bzpib2JAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwczovL3JwLmV4YW1wbGUuY29tLyIsImV4cCI6NzcwMjU4ODgwMCwiYXpwIjoiaHR0cHM6Ly9jbGllbnQuZXhhbXBsZS5uZXQvIn0.FuBECPuYlCwb8Z9xGnc3gb4qbsi4-bxLf2lFx258mTNP4E46Y7SCRUNHiumlo1DIR3Q6_izJrCeee1eSszFzEcbxaXWrr0-Wcv7UOvBpBPbtXSB0J9k5p8opKDRlKR6C8PsieAHcyW8x3tbedXm1xnlt-_SeGTmSnOW7H5Neo6c';
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
      expect(Object.keys(claims)).to.have.length(4);
      
      expect(claims.issuer).to.equal('https://op.example.com/');
      expect(claims.audience).to.equal('https://rp.example.com/');
      expect(claims.expiresAt).to.be.an.instanceOf(Date);
      expect(claims.expiresAt.getTime()).to.equal(7702588800000);
      expect(claims.authorizedPresenter).to.equal('https://client.example.net/');
    });
  });
  
  describe('decoding a valid SAT that contains an acceptable nbf claim', function() {
    // header = { alg: 'RS256' }
    // body = { iss: 'https://op.example.com/',
    //          sub: 'mailto:bob@example.com',
    //          aud: 'https://rp.example.com/',
    //          exp: 7702588800,
    //          nbf: 1328083200 }
    var data = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL29wLmV4YW1wbGUuY29tLyIsInN1YiI6Im1haWx0bzpib2JAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwczovL3JwLmV4YW1wbGUuY29tLyIsImV4cCI6NzcwMjU4ODgwMCwibmJmIjoxMzI4MDgzMjAwfQ.LSHYY8zYG385AZnFTLSGnFSGZDHjKTROqruyk9cvTeicDGp7L0izGCCqFfC-gP7g3LvwUmErOLOMuvLnNIl8iRpCM0xNjJ0B6qyT5ISr2AW8uVJIeqiIuGyQj6jkJ1CQzv5uWD8zNsGnzYDWzKCyxpCpXpY7_u_daXy31TX03CY';
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
  
  describe('decoding an invalid SAT due to invalid signature', function() {
    // header = { alg: 'RS256' }
    // body = { iss: 'https://op.example.com/',
    //          sub: 'mailto:bob@example.com',
    //          aud: 'https://rp.example.com/',
    //          exp: 7702588800 }
    var data = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL29wLmV4YW1wbGUuY29tLyIsInN1YiI6Im1haWx0bzpib2JAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwczovL3JwLmV4YW1wbGUuY29tLyIsImV4cCI6NzcwMjU4ODgwMH0.ZwLZxuaTnxM74q6QO3JRNuruviw1rZDTETNyPNH7EJ-KOnmEWeVNJhhkncrgNIJO0cbDakW2XVUWeiviYtXQMV0Yyp78uCXM6WB5b7w2i_3Z77rOic2YMnDr0qYBG-hvPdHZ05W_WkOMhEbWZZadWjkdVnbJ2ZzjdHdMStFxcAX';
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
      expect(error.message).to.equal('Token signature invalid');
      expect(error.code).to.equal('ENOTVALID');
    });
    
    it('should not decode token', function() {
      expect(claims).to.be.undefined;
    });
  });
  
  describe('decoding an invalid SAT due to audience mismatch', function() {
    // header = { alg: 'RS256' }
    // body = { iss: 'https://op.example.com/',
    //          sub: 'mailto:bob@example.com',
    //          aud: 'https://rpx.example.com/',
    //          exp: 7702588800,
    //          azp: 'https://client.example.net/' }
    var data = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL29wLmV4YW1wbGUuY29tLyIsInN1YiI6Im1haWx0bzpib2JAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwczovL3JweC5leGFtcGxlLmNvbS8iLCJleHAiOjc3MDI1ODg4MDAsImF6cCI6Imh0dHBzOi8vY2xpZW50LmV4YW1wbGUubmV0LyJ9.KYan0ZM01zW_ujIpBgmrI_vyweeHMz5rYeqxGCabNhu-MpIrN5jtzteUwae8EXEO-eDIzE3c0WJzVWJ100fsSzsWikmqdiz6moz-P23UZjiF2VeNcq-TlzmunPhL36lwMKas5sH473_r1zQRz768k3taxqHnKuoG-LTWxa8XjA8';
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
      expect(error.message).to.equal('Token not intended for this audience');
      expect(error.code).to.equal('ENOTVALID');
    });
    
    it('should not decode token', function() {
      expect(claims).to.be.undefined;
    });
  });
  
  describe('decoding an invalid SAT due to audience list mismatch', function() {
    // header = { alg: 'RS256' }
    // body = { iss: 'https://op.example.com/',
    //          sub: 'mailto:bob@example.com',
    //          aud: [ 'https://rpx.example.com/', 'https://rpy.example.com/', 'https://rpz.example.com/' ],
    //          exp: 7702588800,
    //          azp: 'https://client.example.net/' }
    var data = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL29wLmV4YW1wbGUuY29tLyIsInN1YiI6Im1haWx0bzpib2JAZXhhbXBsZS5jb20iLCJhdWQiOlsiaHR0cHM6Ly9ycHguZXhhbXBsZS5jb20vIiwiaHR0cHM6Ly9ycHkuZXhhbXBsZS5jb20vIiwiaHR0cHM6Ly9ycHouZXhhbXBsZS5jb20vIl0sImV4cCI6NzcwMjU4ODgwMCwiYXpwIjoiaHR0cHM6Ly9jbGllbnQuZXhhbXBsZS5uZXQvIn0.AxstQhWamrWWXRGXVo-D6XdXfPuEqO5x8M35rvRVRCrA8sf4zKZOhk7PAXEtaRS7_9bb8B0gsIMAdjkL5pCdUi6PNlcx9gqo7WzWOd6-sV8mDGjFkIaqQT2jFaHIjohUmNquS9Vuy5j2ntOTt26kDO0Je_LzGjNpFW1SlJHQD4Q';
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
      expect(error.message).to.equal('Token not intended for this audience');
      expect(error.code).to.equal('ENOTVALID');
    });
    
    it('should not decode token', function() {
      expect(claims).to.be.undefined;
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
  
  describe('decoding an invalid SAT due to missing sub claim', function() {
    var data = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL29wLmV4YW1wbGUuY29tLyIsImF1ZCI6Imh0dHBzOi8vcnAuZXhhbXBsZS5jb20vIiwiZXhwIjo3NzAyNTg4ODAwfQ.OR1DUc8DFeedLOPvWV_6gTyFLYgbwaqDWn6nryoq4Q9phfnC3Hd7W1KGmTzjR6WTFnEiNCfddH_XBirZnkXB29nVOtGAclbEbhA0Q7lpuCZYw0XY6Y3X9_5NhubvsbCVUCaN8qZET1nZGtSsl_1Lpd5NUBCgg36e9QgBbvE8Fow';
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
      expect(error.message).to.equal('Token missing required claim: sub');
      expect(error.code).to.equal('ENOTVALID');
    });
    
    it('should not decode token', function() {
      expect(claims).to.be.undefined;
    });
  });
  
  describe('decoding an invalid SAT due to missing aud claim', function() {
    var data = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL29wLmV4YW1wbGUuY29tLyIsInN1YiI6Im1haWx0bzpib2JAZXhhbXBsZS5jb20iLCJleHAiOjc3MDI1ODg4MDB9.ATccuoB6C6djyeH7tDVdZNpni2UPuu7at6M3svCy4FswpVn8rNFPf6h0tNsP4WbIk6GHBWD23QGEv2FtMP3xOCcn04SDgHhGByVJqjgiDPK5PtKZ6vtdLhHoUWBSuWaWrGjbFUv0WP73bUmt2SBAxw_iwYJOAzabujgpTW7-kHc';
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
      expect(error.message).to.equal('Token missing required claim: aud');
      expect(error.code).to.equal('ENOTVALID');
    });
    
    it('should not decode token', function() {
      expect(claims).to.be.undefined;
    });
  });
  
  describe('decoding an invalid SAT due to missing exp claim', function() {
    var data = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL29wLmV4YW1wbGUuY29tLyIsInN1YiI6Im1haWx0bzpib2JAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwczovL3JwLmV4YW1wbGUuY29tLyJ9.FcgA2ZMu0AiAmtJMLWs9Hg5SbYH2dbGFYfMWy6nf-6VQMFmVks2u2UdOPXZQ3VVfXm_DMsDZgTX92lUDgD4v-ZuW-ZtehpnBsSMf5g8rgo5kKbuOvv7K0R5mmIdDtmpKvTd0GrkSrLzQkjGbuosQVaz-McEnvNNOHVYFXuCwmk8';
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
      expect(error.message).to.equal('Token missing required claim: exp');
      expect(error.code).to.equal('ENOTVALID');
    });
    
    it('should not decode token', function() {
      expect(claims).to.be.undefined;
    });
  });
  
  describe('decoding an invalid SAT due to being expired', function() {
    var data = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL29wLmV4YW1wbGUuY29tLyIsInN1YiI6Im1haWx0bzpib2JAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwczovL3JwLmV4YW1wbGUuY29tLyIsImV4cCI6OTE3ODU2MDAwfQ.V8zlO3A6WLN1oAekhYfOKHltxoaTF-PZY-5vH-aWHTzOfjWSamG5F48Ytc2yKWzBuq48ySAruB6f0Kh_7MWnWUDyz0erXPJSHAYHUmq_oo121pyb6-7RjKZrpD8MDCrsjEkREHZOJFWjhWWnpydC8OVmXWk197uaf4NxhzEhjOg';
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
      expect(error.message).to.equal('Token expired');
      expect(error.code).to.equal('ENOTVALID');
    });
    
    it('should not decode token', function() {
      expect(claims).to.be.undefined;
    });
  });
  
  describe('decoding an invalid SAT due to being not yet acceptable', function() {
    var data = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL29wLmV4YW1wbGUuY29tLyIsInN1YiI6Im1haWx0bzpib2JAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwczovL3JwLmV4YW1wbGUuY29tLyIsImV4cCI6NzcwMjU4ODgwMCwibmJmIjo3NjcxMDUyODAwfQ.pnMRenhW2uN8XU1BZ4KPPReMob4ddt0Jk1P9sfd60KxZOoCcLhkDuD3Ay1CjX2FCR9Tk-vEb_w2lA_h3Ifebij_rhJ49acZmB0XWQE_O6G7ubewzBCc6_jYfybMgMx6nl7AyRaXYcOTP9-blWsDWJ328cm1bSKCnyXMbVP_oRwM';
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
      expect(error.message).to.equal('Token not yet acceptable');
      expect(error.code).to.equal('ENOTVALID');
    });
    
    it('should not decode token', function() {
      expect(claims).to.be.undefined;
    });
  });
  
  
  describe('without audience option', function() {
    
    describe('decoding a valid SAT', function() {
      // header = { alg: 'RS256' }
      // body = { iss: 'https://op.example.com/',
      //          sub: 'mailto:bob@example.com',
      //          aud: 'https://rp.example.com/',
      //          exp: 7702588800 }
      var data = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL29wLmV4YW1wbGUuY29tLyIsInN1YiI6Im1haWx0bzpib2JAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwczovL3JwLmV4YW1wbGUuY29tLyIsImV4cCI6NzcwMjU4ODgwMH0.ZwLZxuaTnxM74q6QO3JRNuruviw1rZDTETNyPNH7EJ-KOnmEWeVNJhhkncrgNIJO0cbDakW2XVUWeiviYtXQMV0Yyp78uCXM6WB5b7w2i_3Z77rOic2YMnDr0qYBG-hvPdHZ05W_WkOMhEbWZZadWjkdVnbJ2ZzjdHdMStFxcA0';
      var claims, error;
    
      before(function(done) {
        function keying(issuer, done) {
          expect(issuer).to.equal('https://op.example.com/');
        
          return fs.readFile(__dirname + '/../keys/rsa/cert.pem', 'utf8', done);
        }
        var decode = sat(keying);
      
        decode(data, function(err, c) {
          error = err;
          claims = c;
          done();
        });
      });
    
      it('should error', function() {
        expect(error).to.be.an.instanceOf(Error);
        expect(error.message).to.equal('Token not intended for this audience');
        expect(error.code).to.equal('ENOTVALID');
      });
    
      it('should not decode token', function() {
        expect(claims).to.be.undefined;
      });
    });
    
  });
  
  describe('with audience list option', function() {
    
    describe('decoding a valid SAT with audience that matches', function() {
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
        var decode = sat({ audience: [ 'https://rp1.example.com/', 'https://rp.example.com/' ] }, keying);
      
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
    
    describe('decoding a valid SAT with one audience that matches', function() {
      // header = { alg: 'RS256' }
      // body = { iss: 'https://op.example.com/',
      //          sub: 'mailto:bob@example.com',
      //          aud: [ 'https://rp1.example.com/', 'https://rp2.example.com/' ],
      //          exp: 7702588800 }
      var data = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL29wLmV4YW1wbGUuY29tLyIsInN1YiI6Im1haWx0bzpib2JAZXhhbXBsZS5jb20iLCJhdWQiOlsiaHR0cHM6Ly9ycDEuZXhhbXBsZS5jb20vIiwiaHR0cHM6Ly9ycDIuZXhhbXBsZS5jb20vIl0sImV4cCI6NzcwMjU4ODgwMH0.Gjj10zi22VQlgmIPPr6F7X9cI20ygufekO4JFWFsJ3OEMRZQEsgkqsLWM06wrQ3BYQ-gecO-KmpRY8D949C175PuQH9IfvfYoN5BdyZAQSe6-xmuPqSzYySFPQh5JVrBtVhGA0dwOIPA2474Cndq0wf6t4U-SWpcKiFqhAtssLw';
      var claims;
    
      before(function(done) {
        function keying(issuer, done) {
          expect(issuer).to.equal('https://op.example.com/');
        
          return fs.readFile(__dirname + '/../keys/rsa/cert.pem', 'utf8', done);
        }
        var decode = sat({ audience: [ 'https://rp1.example.com/', 'https://rp.example.com/' ] }, keying);
      
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
        expect(claims.audience).to.be.an('array');
        expect(claims.audience[0]).to.equal('https://rp1.example.com/');
        expect(claims.audience[1]).to.equal('https://rp2.example.com/');
        expect(claims.expiresAt).to.be.an.instanceOf(Date);
        expect(claims.expiresAt.getTime()).to.equal(7702588800000);
      });
    });
    
    describe('decoding an invalid SAT due to audience mismatch', function() {
      // header = { alg: 'RS256' }
      // body = { iss: 'https://op.example.com/',
      //          sub: 'mailto:bob@example.com',
      //          aud: 'https://rpx.example.com/',
      //          exp: 7702588800,
      //          azp: 'https://client.example.net/' }
      var data = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL29wLmV4YW1wbGUuY29tLyIsInN1YiI6Im1haWx0bzpib2JAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwczovL3JweC5leGFtcGxlLmNvbS8iLCJleHAiOjc3MDI1ODg4MDAsImF6cCI6Imh0dHBzOi8vY2xpZW50LmV4YW1wbGUubmV0LyJ9.KYan0ZM01zW_ujIpBgmrI_vyweeHMz5rYeqxGCabNhu-MpIrN5jtzteUwae8EXEO-eDIzE3c0WJzVWJ100fsSzsWikmqdiz6moz-P23UZjiF2VeNcq-TlzmunPhL36lwMKas5sH473_r1zQRz768k3taxqHnKuoG-LTWxa8XjA8';
      var claims, error;
    
      before(function(done) {
        function keying(issuer, done) {
          expect(issuer).to.equal('https://op.example.com/');
        
          return fs.readFile(__dirname + '/../keys/rsa/cert.pem', 'utf8', done);
        }
        var decode = sat({ audience: [ 'https://rp1.example.com/', 'https://rp.example.com/' ] }, keying);
      
        decode(data, function(err, c) {
          error = err;
          claims = c;
          done();
        });
      });
    
      it('should error', function() {
        expect(error).to.be.an.instanceOf(Error);
        expect(error.message).to.equal('Token not intended for this audience');
        expect(error.code).to.equal('ENOTVALID');
      });
    
      it('should not decode token', function() {
        expect(claims).to.be.undefined;
      });
    });
  
    describe('decoding an invalid SAT due to audience list mismatch', function() {
      // header = { alg: 'RS256' }
      // body = { iss: 'https://op.example.com/',
      //          sub: 'mailto:bob@example.com',
      //          aud: [ 'https://rpx.example.com/', 'https://rpy.example.com/', 'https://rpz.example.com/' ],
      //          exp: 7702588800,
      //          azp: 'https://client.example.net/' }
      var data = 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL29wLmV4YW1wbGUuY29tLyIsInN1YiI6Im1haWx0bzpib2JAZXhhbXBsZS5jb20iLCJhdWQiOlsiaHR0cHM6Ly9ycHguZXhhbXBsZS5jb20vIiwiaHR0cHM6Ly9ycHkuZXhhbXBsZS5jb20vIiwiaHR0cHM6Ly9ycHouZXhhbXBsZS5jb20vIl0sImV4cCI6NzcwMjU4ODgwMCwiYXpwIjoiaHR0cHM6Ly9jbGllbnQuZXhhbXBsZS5uZXQvIn0.AxstQhWamrWWXRGXVo-D6XdXfPuEqO5x8M35rvRVRCrA8sf4zKZOhk7PAXEtaRS7_9bb8B0gsIMAdjkL5pCdUi6PNlcx9gqo7WzWOd6-sV8mDGjFkIaqQT2jFaHIjohUmNquS9Vuy5j2ntOTt26kDO0Je_LzGjNpFW1SlJHQD4Q';
      var claims, error;
    
      before(function(done) {
        function keying(issuer, done) {
          expect(issuer).to.equal('https://op.example.com/');
        
          return fs.readFile(__dirname + '/../keys/rsa/cert.pem', 'utf8', done);
        }
        var decode = sat({ audience: [ 'https://rp1.example.com/', 'https://rp.example.com/' ] }, keying);
      
        decode(data, function(err, c) {
          error = err;
          claims = c;
          done();
        });
      });
    
      it('should error', function() {
        expect(error).to.be.an.instanceOf(Error);
        expect(error.message).to.equal('Token not intended for this audience');
        expect(error.code).to.equal('ENOTVALID');
      });
    
      it('should not decode token', function() {
        expect(claims).to.be.undefined;
      });
    });
    
  });
  
});
