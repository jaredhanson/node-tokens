var setup = require('../../../lib/types/access/decode');


describe('types/access/decode', function() {
  
  describe('an access token', function() {
    var msg;
    
    before(function(done) {
      var claims = {
        sub: '1',
        scope: 'read:foo write:foo read:bar',
        client_id: 's6BhdRkqt3',
      }
      
      var decode = setup();
      decode(claims, function(err, m) {
        if (err) { return done(err); }
        msg = m;
        done();
      });
    });
    
    it('should decode', function() {
      expect(msg).to.deep.equal({
        user: { id: '1' },
        scope: [ 'read:foo', 'write:foo', 'read:bar' ],
        client: { id: 's6BhdRkqt3' },
      });
    });
  }); // an access token
  
});
