var sat = require('../../lib/decode/sat')
  , fs = require('fs')
  , jws = require('jws');


describe('decode.sat', function() {
  
  it('should be named sat', function() {
    expect(sat().name).to.equal('sat');
  });
  
});
  