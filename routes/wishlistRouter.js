const router = require('express').Router();
const WishlistController = require('../controllers/WishlistController');

router.post('/add', WishlistController.addwishlist);
router.get('/', WishlistController.wishlists);

module.exports = router