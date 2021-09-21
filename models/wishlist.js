'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class Wishlist extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      // define association here
      Wishlist.belongsTo(models.User)
    }
  };
  Wishlist.init({
    name: {
      type: DataTypes.STRING,
      validate: {
        notEmpty: {
          msg: 'Name is required'
        }
      }
    },
    price: {
      type: DataTypes.INTEGER,
      validate: {
        notEmpty: {
          msg: 'Price is required'
        }
      }
    },
    imagerUrl: {
      type: DataTypes.STRING,
      validate: {
        notEmpty: {
          msg: 'Image is required'
        }
      }
    },
    color: {
      type: DataTypes.STRING,
      validate: {
        notEmpty: {
          msg: 'Color is required'
        }
      }
    }
  }, {
    sequelize,
    modelName: 'Wishlist',
  });
  return Wishlist;
};