var jws = require('jws')
  , fs = require('fs');


var payload = {
  iss: 'https://op.example.com/',
  aud: 'https://rp.example.com/',
  exp: Math.floor(new Date(2214, 01, 01).getTime() / 1000)
};

var data = jws.sign({
  header: { alg: 'RS256' },
  payload: payload,
  privateKey: fs.readFileSync('../../test/keys/rsa/private-key.pem')
});

console.log(data);
