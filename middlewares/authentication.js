const { verify } = require('../helpers/jwt');
const { User } = require('../models');

async function authentication(req, res, next) {
    try {
        const token = req.headers.access_token; 
        const payload = verify(token);

        const foundUser = await User.findOne({
            where: {
                email: payload.email
            }
        })
        
        if (!foundUser) {
            throw {
                name: "authentication",
                message: "User Not Found"
            }
        }
        
        req.user = {
            id: foundUser.id,
            email: foundUser.email
        }
        next();
    } catch (err) {
        if (err.message === "User Not Found") {
            next(err);
        } else {
            next({
                name: "authentication",
                message: "Error Authentication"
            });
        }
    }
}

module.exports = authentication;