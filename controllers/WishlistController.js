const { Wishlist } = require('../models');

class WishlistController {
    static async addwishlist(req, res, next) {
        try {
            const { name, price, imageUrl, color, code } = req.body;
            const UserId = req.user.id;
            const result = await Wishlist.create({ name, price, imageUrl, color, code, UserId })
            res.status(201).json(result)
        } catch (err) {
            next(err)
        }
    }

    static async wishlists(req, res, next) {
        try {
            const UserId = req.user.id;
            
            const products = await Wishlist.findAll({
                where: {
                    UserId
                }
            })
            res.status(200).json(products)
        } catch (err) {
            next(err)
        }
    }
}

module.exports = WishlistController;