const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL,
        type: 'OAuth2',
        accessToken: process.env.accessToken
    }
})

function sendEmail(email, name, price, color) {
    const options = {
        from: "'Hacktiv Store' <no-reply@gmail.com>",
        to: email,
        subject: "Your Wishlist",
        text: `
        ${name} was added to your Wishlist
            Product Name: ${name}
            Price: ${price}
            Color: ${color}
        `
    };

    transporter.sendMail(options, (err, info) => {
        if (err) {
            console.log(err);
        } else {
            console.log('berhasil');
        }
    })
}

module.exports = sendEmail;