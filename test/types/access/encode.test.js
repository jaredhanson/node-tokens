var setup = require('../../../lib/types/access/encode');


describe('types/access/encode', function() {
  
  describe('an access token', function() {
    var claims;
    
    before(function(done) {
      var msg = {
        user: {
          id: '1',
          displayName: 'John Doe'
        },
        client: {
          id: 's6BhdRkqt3',
          name: 'Example Client'
        },
        permissions: [ {
          resource: {
            id: '112210f47de98100',
            identifier: 'https://api.example.com/'
          },
          scope: [ 'read:foo', 'write:foo', 'read:bar' ]
        } ]
      }
      
      var encode = setup();
      encode(msg, function(err, c) {
        if (err) { return done(err); }
        console.log(c)
        
        claims = c;
        done();
      });
    });
    
    it('should encode', function() {
      expect(claims).to.deep.equal({
        sub: '1',
        aud: 'https://api.example.com/',
        scope: 'read:foo write:foo read:bar',
        client_id: 's6BhdRkqt3',
      });
    });
  }); // an authorization code
  
});
