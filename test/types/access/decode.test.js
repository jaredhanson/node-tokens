var setup = require('../../../lib/types/access/decode');


describe('types/access/decode', function() {
  
  describe('an access token', function() {
    var message;
    
    before(function(done) {
      var claims = {
        sub: '1',
        aud: 'https://api.example.com/',
        scope: 'read:foo write:foo read:bar',
        client_id: 's6BhdRkqt3',
      }
      
      var decode = setup();
      decode(claims, {}, function(err, m) {
        if (err) { return done(err); }
        message = m;
        done();
      });
    });
    
    it('should decode', function() {
      expect(message).to.deep.equal({
        user: { id: '1' },
        client: { id: 's6BhdRkqt3' },
      });
    });
  }); // an authorization code
  
});
