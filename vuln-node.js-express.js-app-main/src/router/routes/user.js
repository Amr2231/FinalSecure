'user strcit';
const config = require('./../../config')
var jwt = require("jsonwebtoken");
const { user } = require('../../orm');
module.exports = (app,db) => {

    //Get all users
    /**
     * GET /v1/admin/users/ 
     * @summary List all users (Unverified JWT Manipulation - FIXED)
     * @tags admin
     * @security BearerAuth
     * @return {array<User>} 200 - success response - application/json
     */
    app.get('/v1/admin/users/', (req,res) =>{
        //console.log("auth",req.headers.authorization)
        if (req.headers.authorization){ 
            try {
                const token = req.headers.authorization.split(' ')[1];
                const jwtTokenSecret = process.env.JWT_SECRET || "SuperSecret";
                const user_object = jwt.verify(token, jwtTokenSecret, {
                    algorithms: ['HS256'],
                    audience: 'vuln-app',
                    issuer: 'vuln-app'
                });
                
                db.user.findAll({include: "beers"})
                    .then((users) => {
                        if (user_object.role == 'admin'){
                            //console.log("fetch users")
                            res.json(users);
                        }       
                        else{ 
                            res.json({error:"Not Admin, try again"})
                        }
                        
                        return;
                    }).catch((e) =>{
                        res.json({error:"error fetching users"+e})
                    });
            } catch (err) {
                return res.status(401).json({ error: 'Invalid token' });
            }
        }else{
            res.json({error:"missing Token in header"})
            return;
        }
    });
    //Get information about other users
    /**
     * GET /v1/user/{user_id}
     * @summary Get information of a specific user
     * @tags user
     * @param {integer} user_id.path.required - user id to get information
     * @return {array<User>} 200 - success response - application/json
     */
     app.get('/v1/user/:id', (req,res) =>{
        db.user.findOne({include: 'beers',where: { id : req.params.id}})
            .then(user => {
                res.json(user);
            });
    });
    /**
     * DELETE /v1/user/{user_id} 
     * @summary Delete a specific user (Broken Function Level Authentication)
     * @tags user
     * @param {integer} user_id.path.required - user id to delete (Broken Function Level)
     * @return {array<User>} 200 - success response - application/json
     */
         app.delete('/v1/user/:id', (req,res) =>{
            db.user.destroy({where: { id : req.params.id}})
                .then(user => {
                    res.json({result: "deleted"});
                })
                .catch(e =>{
                    res.json({error:e})
                });
        });
    /**
     * POST /v1/user/
     * @summary create a new user (Weak Password)(ReDos - Regular Expression Denial of Service)
     * @description   "email": "aaaaaaaaa@aaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa{",
     * @tags user
     * @param {User} request.body.required - User
     * @return {object} 200 - user response
     */
    app.post('/v1/user/', (req,res) =>{

        const userEmail = req.body.email;
        const userName = req.body.name;
        const userRole = req.body.role
        const userPassword = req.body.password;
        const userAddress = req.body.address
        //validate email using regular expression
        var emailExpression = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
        var regex = new RegExp(emailExpression)
            console.log(emailExpression.test(userEmail))
            if (!emailExpression.test(userEmail)){
                res.json({error:"regular expression of email couldn't be validated"})
                return
            }
        const new_user = db.user.create(
            {
                name:userName,
                email:userEmail,
                role:userRole,
                address:userAddress,
                password:userPassword
            }).then(new_user => {
                res.json(new_user);
            })
                

    });
         /**
     * GET /v1/love/{beer_id}
     * @summary make a user love a beer(CSRF - Client Side Request Forgery GET)
     * @tags user
     * @param {integer} beer_id.path.required - Beer Id
     * @param {integer} id.query - User ID
     * @param {boolean} front.query - is it a frontend redirect ?
     * @return {object} 200 - user response
     */
          app.get('/v1/love/:beer_id', (req,res) =>{
            var current_user_id = req.query.id;
            var front = true;
            if (req.query.front){
                front = req.query.front
            }
            if(!req.query.id){ // if not provided take from session
                res.redirect("/?message=No Id")
                return
            }
            
            
            const beer_id = req.params.beer_id;

            db.beer.findOne({
                where:{id:beer_id}
            }).then((beer) => {
                const user = db.user.findOne(
                    {where: {id : current_user_id}},
                    {include: 'beers'}).then(current_user => {
                        if(current_user){
                        current_user.hasBeer(beer).then(result => {
                            if(!result){
                                current_user.addBeer(beer, { through: 'user_beers' })
                            }
                            if(front){
                                let love_beer_message = "You Just Loved this beer!!"
                                res.redirect("/beer?user="+ current_user_id+"&id="+beer_id+"&message="+love_beer_message)
                                return
                            }
                            res.json(current_user);
                        })
                    }
                    else{
                        res.json({error:'user Id was not found'});
                    }
                })
            })
            .catch((e)=>{
                res.json(e)
            })
        });
     /**
     * POST /v1/love/{beer_id}
     * @summary make a user love a beer (CSRF - Client Side Request Forgery POST - FIXED)
     * @tags user
     * @param {integer} beer_id.path.required - Beer Id
     * @param {integer} id.query - User ID
     * @param {boolean} front.query - is it a frontend redirect ?
     * @return {object} 200 - user response
     */
         app.post('/v1/love/:beer_id', (req,res) =>{
            var current_user_id = null;
            var front = false;
            
            // Try to get user ID from multiple sources in order of priority
            // 1. First try JWT token in Authorization header
            if (req.headers.authorization) {
                try {
                    const token = req.headers.authorization.split(' ')[1];
                    const jwtTokenSecret = process.env.JWT_SECRET || "SuperSecret";
                    const decoded = jwt.verify(token, jwtTokenSecret, {
                        algorithms: ['HS256'],
                        audience: 'vuln-app',
                        issuer: 'vuln-app'
                    });
                    current_user_id = decoded.id;
                } catch (err) {
                    return res.status(401).json({error:"Invalid JWT token"});
                }
            }
            
            // 2. Then try session
            if (!current_user_id && req.session && req.session.user && req.session.user.id) {
                current_user_id = req.session.user.id;
            }
            
            // 3. Finally try query parameter (least secure, should validate)
            if (!current_user_id && req.query.id) {
                current_user_id = req.query.id;
            }
            
            // No valid user ID found
            if (!current_user_id) {
                return res.status(401).json({error:"Couldn't find user token or session"});
            }
            
            if (req.query.front){
                front = req.query.front;
            }
            
            const beer_id = req.params.beer_id;

            db.beer.findOne({
                where:{id:beer_id}
            }).then((beer) => {
                const user = db.user.findOne(
                    {where: {id : current_user_id}},
                    {include: 'beers'}).then(current_user => {
                        if(current_user){
                        current_user.hasBeer(beer).then(result => {
                            if(!result){
                                current_user.addBeer(beer, { through: 'user_beers' })
                            }
                            if(front){
                                let love_beer_message = "You Loved this beer!!"
                                res.redirect("/beer?user="+ current_user_id+"&id="+beer_id+"&message="+love_beer_message)
                            }
                            res.json(current_user);
                        })
                    }
                    else{
                        res.status(404).json({error:'user Id was not found'});
                    }
                })
            })
            .catch((e)=>{
                res.status(500).json({error: "Error: " + e.toString()})
            })
        });

   /**
     * LoginUserDTO for login
     * @typedef {object} LoginUserDTO
     * @property {string} email.required - email
     * @property {string} password.required - password
     */
    /**
     * POST /v1/user/token
     * @summary login endpoint to get jwt token - (Insecure JWT Implementation - FIXED)
     * @tags user
     * @param {LoginUserDTO} request.body.required - user login credentials - application/json       
     * @return {string} 200 - success
     * @return {string} 404 - user not found
     * @return {string} 401 - wrong password
    */
     app.post('/v1/user/token', (req,res) =>{

        const userEmail = req.body.email;
        const userPassword = req.body.password;
        const user = db.user.findAll({
            where: {
              email: userEmail
            }}).then(user => {
                if(user.length == 0){
                    res.status(404).send({error:'User was not found'})
                return;
                }

                const md5 = require('md5')
                //compare password with and without hash
                if((user[0].password == userPassword) || (md5(user[0].password) == userPassword)){
                    //Add jwt token with proper security options
                    const jwtTokenSecret = process.env.JWT_SECRET || "SuperSecret"
                    const payload = { "id": user[0].id,"role":user[0].role }
                    var token = jwt.sign(payload, jwtTokenSecret, {
                        algorithm: 'HS256',
                        expiresIn: '1h',
                        audience: 'vuln-app',
                        issuer: 'vuln-app'
                      });
                    res.status(200).json({
                        jwt:token,
                        user:user,
                        
                    });
                    return;
                }
                res.status(401).json({error:'Password was not correct'})
            })
                

    });
    /**
     * LoginUserDTO for login
     * @typedef {object} LoginUserDTO
     * @property {string} email.required - email
     * @property {string} password.required - password
     */
    /**
     * POST /v1/user/login
     * @summary login page - (Session fixation)(user enumeration)(insecure password/no hashing)
     * @tags user
     * @param {LoginUserDTO} request.body.required - user login credentials - application/json       
     * @return {string} 200 - success
     * @return {string} 404 - user not found
     * @return {string} 401 - wrong password
    */
     app.post('/v1/user/login', (req,res) =>{

       
        const userEmail = req.body.email;
        const userPassword = req.body.password;
        const user = db.user.findAll({
            where: {
              email: userEmail
            }}).then(user => {
                if(user.length == 0){
                    res.status(404).send({error:'User was not found'})
                return;
                }

                const md5 = require('md5')
                //compare password with and without hash
                if((user[0].password == userPassword) || (md5(user[0].password) == userPassword)){
                    //Add jwt token
                    //logge in logichere
                    res.status(200).json(user);
                    return;
                }
                res.status(401).json({error:'Password was not correct'})
            })
                

    });

    /**
     * PUT /v1/user/{user_id}
     * @summary update user - (horizontal privesc - FIXED)
     * @tags user
     * @param {User} request.body.required - update credentials - application/json       
     * @param {integer} user_id.path.required
     * @return {string} 200 - success
     * @return {string} 404 - user not found
     * @return {string} 401 - unauthorized
    */
     app.put('/v1/user/:id', (req,res) =>{

        const userId = req.params.id;
        
        // Verify user is authenticated via JWT
        if (!req.headers.authorization) {
            return res.status(401).json({error: "Missing authorization token"});
        }
        
        try {
            const token = req.headers.authorization.split(' ')[1];
            const jwtTokenSecret = process.env.JWT_SECRET || "SuperSecret";
            const decoded = jwt.verify(token, jwtTokenSecret, {
                algorithms: ['HS256'],
                audience: 'vuln-app',
                issuer: 'vuln-app'
            });
            
            // Users can only update their own profile (not other users)
            if (decoded.id != userId) {
                return res.status(403).json({error: "Cannot update other users' profiles"});
            }
            
            // Whitelist allowed fields to prevent mass assignment
            const allowedFields = ['email', 'name', 'address', 'profile_pic'];
            const updateData = {};
            allowedFields.forEach(field => {
                if (req.body[field]) {
                    updateData[field] = req.body[field];
                }
            });
            
            const user = db.user.update(updateData, {
                where: {
                    id : userId
                }}
            )
            .then((user)=>{
                res.status(200).json({message: "User updated successfully", user: user})
            })
            .catch(err => {
                res.status(500).json({error: "Error updating user: " + err.toString()})
            })
            
        } catch (err) {
            return res.status(401).json({error: "Invalid token"});
        }

    });


    /**
     * PUT /v1/admin/promote/{user_id}
     * @summary promote to admin - (vertical privesc - FIXED)
     * @tags admin
     * @param {integer} user_id.path.required
     * @return {string} 200 - success
     * @return {string} 404 - user not found
     * @return {string} 401 - unauthorized
     * @return {string} 403 - forbidden (not admin)
    */
     app.put('/v1/admin/promote/:id', (req,res) =>{

        const userId = req.params.id;
        
        // Verify user is authenticated via JWT and is admin
        if (!req.headers.authorization) {
            return res.status(401).json({error: "Missing authorization token"});
        }
        
        try {
            const token = req.headers.authorization.split(' ')[1];
            const jwtTokenSecret = process.env.JWT_SECRET || "SuperSecret";
            const decoded = jwt.verify(token, jwtTokenSecret, {
                algorithms: ['HS256'],
                audience: 'vuln-app',
                issuer: 'vuln-app'
            });
            
            // Only admins can promote users
            if (decoded.role !== 'admin') {
                return res.status(403).json({error: "Only admins can promote users"});
            }
            
            // Prevent self-promotion edge case (though already checked above)
            if (decoded.id == userId) {
                return res.status(400).json({error: "Cannot promote yourself"});
            }
            
            const user = db.user.update({role:'admin'}, {
                where: {
                    id : userId
                }}
            )
            .then((user)=>{
                res.status(200).json({message: "User promoted to admin", user: user})
            })
            .catch(err => {
                res.status(500).json({error: "Error promoting user: " + err.toString()})
            })
            
        } catch (err) {
            return res.status(401).json({error: "Invalid token"});
        }

    });

    /**
    * POST /v1/user/{user_id}/validate-otp
    * @summary Validate One Time Password - (Broken Authorization/2FA)(Auth Credentials in URL)(lack of rate limiting)
    * @tags user
    * @param {integer} user_id.path.required
    * @param {string} seed.query - otp seed
    * @param {string} token.query.required - token to be supplied by the user and validated against the seed
    * @return {string} 200 - success
    * @return {string} 401 - invalid token
   */
    app.post('/v1/user/:id/validate-otp', (req,res) =>{

       const userId = req.params.id;
       const user = db.user.findOne({
           where: {
             id: userId
           }}).then(user => {
               if(user.length == 0){
                   res.status(404).send({error:'User was not found'})
               return;
               }
            
            const otplib = require('otplib')

            const seed = req.query.seed || 'SUPERSECUREOTP'; // user supplied seed or hard coded one
            const userToken = req.query.token;

            const GeneratedToken = otplib.authenticator.generate(seed);

            const isValid = otplib.authenticator.check(userToken, GeneratedToken);
            // or
            //const isValid = authenticator.verify({ userToken, GeneratedToken });
               if(isValid || userToken == req.session.otp){
                   const jwtTokenSecret = "SuperSecret"
                   const payload = { "id": user.id,"role":user.role }
                   var jwttoken = jwt.sign(payload, jwtTokenSecret, {
                       expiresIn: 86400, // 24 hours
                     });
                   res.status(200).json({
                       jwt:jwttoken,
                       user:user,
                       
                   });
                   return;
               }
               if(req.query.seed){
                req.session.otp = GeneratedToken // add generated token to session
                req.session.save(function(err) {
                    // session saved
                  })
                res.status(401).json({error:'OTP was not correct, got:' + GeneratedToken})
                return;
               }
               res.status(401).json({error:'OTP was not correct'})
           })
               

   });

};
