var Tokens = require('../lib/tokens')
  , sinon = require('sinon');


describe('Tokens', function() {
  
  describe('#issue', function() {
    var keyring = new Object();
    keyring.get = sinon.stub().yields(null, { secret: 'keyboardcat' });
    
    var tokens = new Tokens()
      , token;  
      
    var jwt = {
      seal: sinon.stub().yields(null, 'eyJ0.eyJpc3Mi.dBjf')
    };
      
    tokens.use('application/jwt', jwt);
    tokens._keyring = keyring;
  
    describe('to self', function() {
      
      before(function(done) {
        tokens.issue({ beep: 'boop' }, function(err, t) {
          token = t;
          done(err);
        });
      });
      
      it('should do something', function() {
        expect(token).to.equal('eyJ0.eyJpc3Mi.dBjf');
      });
    });
    
  }); // #issue
  
});
