/* global describe, it, expect */

var tokens = require('..');

describe('tokens', function() {
  
  it('should export constructors', function() {
    expect(tokens.Encoder).to.be.a('function');
    expect(tokens.Decoder).to.be.a('function');
  });
  
  it('should export decoding functions', function() {
    expect(tokens.decode).to.be.an('object');
    expect(tokens.decode.sat).to.be.a('function');
    expect(tokens.decode.oauthIntrospection).to.be.a('function');
  });
  
  it('should export encoding functions', function() {
    expect(tokens.encode).to.be.an('object');
    expect(tokens.encode.sat).to.be.a('function');
  });
  
});
