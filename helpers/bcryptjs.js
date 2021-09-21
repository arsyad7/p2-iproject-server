const bcrypt = require('bcryptjs');

function encode(pass) {
    const salt = bcrypt.genSaltSync(10);
    return bcrypt.hashSync(pass, salt);
}

function decode(pass, hash) {
    return bcrypt.compareSync(pass, hash);
}

module.exports = {
    encode,
    decode
}