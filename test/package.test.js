/* global describe, it, expect */

var tokens = require('..');

describe('tokens', function() {
  
  it('should export constructors', function() {
    expect(tokens.OldSealer).to.be.a('function');
    expect(tokens.OldUnsealer).to.be.a('function');
  });
  
  it('should export JWT implementation', function() {
    expect(tokens.jwt.seal).to.be.a('function');
    expect(tokens.jwt.unseal).to.be.a('function')
  });
  
});
