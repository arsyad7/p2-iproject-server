function errorHandler(err, req, res, next) {
    let code = 500;
    let message = ["Internal server Error"];
    
    if (err.name === "SequelizeValidationError") {
        code = 400;
        message = err.errors.map((el) => {
            return el.message;
        });
    } else if (err.name === "ProductNotFound") {
        code = 404;
        message = [err.message];
    } else if(err.name === "authentication") {
        code = 401;
        message = [err.message];
    }
  
    res.status(code).json({ message });
}
  
module.exports = errorHandler;
  