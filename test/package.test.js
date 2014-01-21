/* global describe, it, expect */

var tokens = require('..');

describe('tokens', function() {
  
  it('should export constructors', function() {
    expect(tokens.Encoder).to.be.an('function');
    expect(tokens.Decoder).to.be.an('function');
  });
  
});
