/* global describe, it, expect */

var tokens = require('..');

describe('tokens', function() {
  
  it('should export constructors', function() {
    expect(tokens.Sealer).to.be.a('function');
    expect(tokens.Unsealer).to.be.a('function');
  });
  
  it('should export JWT implementation', function() {
    expect(tokens.jwt.seal).to.be.a('function');
    expect(tokens.jwt.unseal).to.be.a('function')
  });
  
});
