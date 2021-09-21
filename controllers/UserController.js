const { User } = require('../models');
const { encode, decode } = require('../helpers/bcryptjs');
const { sign, verify } = require('../helpers/jwt');

class UserController {
    static async register(req, res, next) {
        try {
            let { username, email, password } = req.body;
            password = encode(password)
            
            const user = await User.create({ username, email, password })
            res.status(201).json({
                id: user.id,
                email: user.email
            })
        } catch (err) {
            next(err)
        }
    }

    static async login(req, res, next) {
        try {
            const { email, password } = req.body;
            const user = await User.findOne({
                where: { email }
            })

            if (user) {
                const isValid = decode(password, user.password);
                if (isValid) {
                    const access_token = sign({
                        id: user.id,
                        email: user.email
                    })
                    req.headers.access_token = access_token;

                    res.status(200).json({ 
                        userId: user.id,
                        email: user.email,
                        username: user.username,
                        access_token
                    });
                } else {
                    throw {
                        name: "authentication",
                        message: "Error invalid username or email or password"
                    }
                }
            } else {
                throw {
                    name: "authentication",
                    message: "Error invalid username or email or password"
                }
            }
        } catch (err) {
            next(err);
        }
    }
}

module.exports = UserController;