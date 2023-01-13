const express = require('express');
const router = express.Router();
const auth = require('../../middleware/auth')
const bcrypt = require('bcryptjs')
const User = require('../../models/User');
const jwt = require('jsonwebtoken')
const config = require('config')
const {check , validationResult } = require('express-validator');
// @Route   Get api/auth
// @Desc    Test Route
// @Access  Public
router.get('/',auth, async (req,res) => {
    try{
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    }
    catch(err){
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});


// @Route   Post api/auth 
// @Desc    Authenticate User and get token 
// @Access  private
router.post('/', 
[
    check('email','Please include valid email').isEmail(),
    check(
        'password',
        'Passwod is required'
    ).exists()
],
async(req,res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty())
    { 
        return res.status(400).json({errors: errors.array()})
    }

    const { email, password} = req.body;

    try{

    // see if user exists
        let user = await User.findOne({email})
        if (!user){
            return res.status(400).json({errors: [{msg: 'Invalid Credentials'}]})
        }
        const isMatch = await bcrypt.compare(password,user.password);
        if(!isMatch){
            return res.status(400).json({errors: [{msg: 'Invalid Credentials'}]})   
        }
    // Return jwt
    const payload = {
        user:{
           id :user.id 
        }
    }
    jwt.sign(payload, config.get('jwtSecret'),
    {expiresIn: '5 days'},
    (err, token) =>{
        if(err) throw err;
        res.json({token })
    });

    }  
    
    catch(err){
        console.error(err.message);
        return res.status(500).send('Server Error');
    }
}
   

);

module.exports = router;