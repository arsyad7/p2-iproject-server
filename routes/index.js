const router = require('express').Router();
const userRouter = require('./userRouter');
const wishlistRouter = require('./wishlistRouter');
const productRouter = require('./productRouter');
const authentication = require('../middlewares/authentication');
const errorHandler = require('../middlewares/errorHandler');

router.use('/users', userRouter);
router.use('/products', productRouter);
router.use(authentication);
router.use('/wishlists', wishlistRouter);
router.use(errorHandler);

module.exports = router