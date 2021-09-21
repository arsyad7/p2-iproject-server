const axios = require('axios');

class ProductController {
    static async list(req, res, next) {
        try {
            let options = {
                method: 'GET',
                url: 'https://apidojo-hm-hennes-mauritz-v1.p.rapidapi.com/products/list',
                params: {
                    country: 'asia2',
                    lang: 'en',
                    currentpage: '0',
                    pagesize: '16',
                    categories: 'men_all',
                    concepts: 'H&M MAN'
                },
                headers: {
                    'x-rapidapi-host': 'apidojo-hm-hennes-mauritz-v1.p.rapidapi.com',
                    'x-rapidapi-key': 'c1db1a4c1amsh50f031aa3320911p12896cjsn8424f927f574'
                }
            };
            // axios.request(options)
            //     .then(function (resp) {
            //         // console.log(resp.data.results[0].articles);
            //         res.status(200).json(resp.data)
            //     })
            //     .catch(function (error) {
            //         console.error(error);
                // });
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
                  'x-rapidapi-key': 'c1db1a4c1amsh50f031aa3320911p12896cjsn8424f927f574'
                }
            };
            // axios.request(options)
            //     .then(function (resp) {
            //         res.status(200).json(resp.data)
            //     })
            //     .catch(function (error) {
            //         console.error(error);
            //     });
        } catch (err) {
            next(err)
        }
    }
}

// 

module.exports = ProductController;