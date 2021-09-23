const axios = require('axios');

class ProductController {
    static async list(req, res, next) {
        try {
            const { page } = req.query;
            page ? page : 0;

            let options = {
                method: 'GET',
                url: 'https://apidojo-hm-hennes-mauritz-v1.p.rapidapi.com/products/list',
                params: {
                    country: 'asia2',
                    lang: 'en',
                    currentpage: page,
                    pagesize: '16',
                    categories: 'men_all',
                    concepts: 'H&M MAN'
                },
                headers: {
                    'x-rapidapi-host': 'apidojo-hm-hennes-mauritz-v1.p.rapidapi.com',
                    'x-rapidapi-key': '425bf39203msh0464899b27387afp1be1a6jsnadbac21fb2bc'
                }
            };
            axios.request(options)
                .then(function (resp) {
                    // console.log(resp.data.results[0].articles);
                    res.status(200).json(resp.data)
                })
                .catch(function (error) {
                    console.error(error);
                });
        } catch (err) {
            next(err)
        }
    }

    static async details(req, res, next) {
        try {
            const code = req.params.code;

            let options = {
                method: 'GET',
                url: 'https://apidojo-hm-hennes-mauritz-v1.p.rapidapi.com/products/detail',
                params: {lang: 'en', productcode: `${code}`, country: 'asia2'},
                headers: {
                  'x-rapidapi-host': 'apidojo-hm-hennes-mauritz-v1.p.rapidapi.com',
                  'x-rapidapi-key': '425bf39203msh0464899b27387afp1be1a6jsnadbac21fb2bc'
                }
            };
            axios.request(options)
                .then(function (resp) {
                    res.status(200).json(resp.data)
                })
                .catch(function (error) {
                    console.error(error);
                });
        } catch (err) {
            next(err)
        }
    }

    static async changeCurrency(req, res, next) {
        try {
            const {currency} = req.body;

            const options = {
                method: 'GET',
                url: 'https://currency-exchange.p.rapidapi.com/exchange',
                params: {to: currency, from: 'SGD', q: '1.0'},
                headers: {
                    'x-rapidapi-host': 'currency-exchange.p.rapidapi.com',
                    'x-rapidapi-key': 'c1db1a4c1amsh50f031aa3320911p12896cjsn8424f927f574'
                }
            };
              
            axios.request(options)
                .then(function (resp) {
                    res.status(200).json(resp.data.toFixed(2))
                })
                .catch(function (error) {
                    console.error(error);
                });
        } catch (err) {
            next(err)
        }
    }
}

module.exports = ProductController;