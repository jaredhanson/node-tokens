var setup = require('../../../lib/jwt/dialect');


describe('types/access/decode', function() {
  
  describe('an access token with scope', function() {
    var msg;
    
    before(function(done) {
      var claims = {
        sub: '248289761001',
        scope: 'profile email',
        client_id: 's6BhdRkqt3',
      }
      
      var dialect = setup();
      dialect.decode(claims, function(err, m) {
        if (err) { return done(err); }
        msg = m;
        done();
      });
    });
    
    it('should decode', function() {
      expect(msg).to.deep.equal({
        user: { id: '248289761001' },
        client: { id: 's6BhdRkqt3' },
        scope: [ 'profile', 'email' ],
      });
    });
  }); // an access token with scope
  
});
