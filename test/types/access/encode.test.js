var setup = require('../../../lib/jwt/dialect');


describe('types/access/encode', function() {
  
  describe('an access token with scope', function() {
    var claims;
    
    before(function(done) {
      var msg = {
        user: {
          id: '248289761001',
          displayName: 'John Doe'
        },
        client: {
          id: 's6BhdRkqt3',
          name: 'Example Client'
        },
        scope: [ 'profile', 'email' ]
      }
      
      var dialect = setup();
      dialect.encode(msg, function(err, c) {
        if (err) { return done(err); }
        claims = c;
        done();
      });
    });
    
    it('should encode', function() {
      expect(claims).to.deep.equal({
        sub: '248289761001',
        client_id: 's6BhdRkqt3',
        scope: 'profile email'
      });
    });
  }); // an access token
  
});
