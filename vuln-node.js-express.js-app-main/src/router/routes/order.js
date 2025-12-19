'user strcit';
var fs = require('fs')
module.exports = (app,db) => {
    //https://github.com/BRIKEV/express-jsdoc-swagger
    //Get all the beers available for ordering
    /**
     * GET /v1/order
     * @summary Use to list all available beer (Excessive Data Exposure - FIXED)
     * @tags beer
     * @return {array<Beer>} 200 - success response - application/json
     */
    app.get('/v1/order', (req,res) =>{
        db.beer.findAll({
            include: {
                model: db.user,
                attributes: ['id', 'username'],
                through: { attributes: [] } // exclude association data
            },
            attributes: ['id', 'beer_id', 'status']
        })
            .then(beer => {
                res.json(beer);
            });
    });
    /**
     * GET /v1/beer-pic/
     * @summary Get a picture of a beer (Path Traversal - FIXED)
     * @note http://localhost:5000/v1/beer-pic/?picture=../.env
     * @param {string} picture.query.required picture identifier
     * @tags beer
     */
     app.get('/v1/beer-pic/', (req,res) =>{
            const path = require('path');
            const filename = req.query.picture ? path.basename(req.query.picture) : '';
            const safeDir = path.join(__dirname, '..', '..', 'uploads');
            const fullPath = path.join(safeDir, filename);

            // Ensure the resolved path is within the safe directory
            if (!fullPath.startsWith(safeDir)) {
              return res.status(400).send('Invalid file');
            }

            fs.readFile(fullPath, function(err, data){
                if (err){
                    res.send("error")
                }else{
                    if(filename.split('.').length == 1)
                    {
                        res.type('image/jpeg')
                        res.send(data)
                        return;
                }
                let buffer = Buffer.from(data, 'utf8');
                res.send(buffer)
                    
                }
                
            })

        
    });
        /**
     * GET /v1/search/{filter}/{query}
     * @summary Search for a specific beer (SQL Injection - FIXED)
     * @description sqlmap -u 'http://localhost:5000/search/id/2*'
     * @tags beer
     * @param {string} query.path - the query to search for
     * @param {string} filter.path - the column
     * @return {array<Beer>} 200 - success response - application/json
     */
         app.get('/v1/search/:filter/:query', (req,res) =>{
            // Whitelist allowed columns to prevent column name injection
            const allowedColumns = ['id', 'name', 'price', 'currency', 'stock', 'picture'];
            const filter = req.params.filter;
            const query = req.params.query;
            
            // Validate filter against whitelist
            if (!allowedColumns.includes(filter)) {
              return res.status(400).send('Invalid filter column');
            }
            
            // Use parameterized query with proper escaping
            const sql = `SELECT * FROM beers WHERE ${filter} = ?`;
            const beers = db.sequelize.query(sql, { 
              replacements: [query],
              type: db.sequelize.QueryTypes.SELECT 
            }).then(beers => {
                res.status(200).send(beers);

                }).catch(function (err) {
                    res.status(501).send("error, query failed: "+err)
                  })
        
        });
};
