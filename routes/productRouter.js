const router = require('express').Router();
const ProductController = require('../controllers/ProductController');

router.get('/', ProductController.list);
router.get('/:code', ProductController.details);

module.exports = router