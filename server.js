const express = require("express");
const path = require("path");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const User = require("./model/user");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const JWT_SECRET = 'sdfugsufgys!@#$%&*(dfgsdufygsduorfygusdyfguiasddfbdsfg';

mongoose.connect('mongodb://localhost:27017/login', {
    useNewUrlParser: true,
    UseUnifiedTopology: true
});

const app = express();
app.use('/', express.static(path.join(__dirname, 'static')));
app.use(bodyParser.json());


app.post('/api/change-password', async (req, res) =>
{
    const {token, newpassword: plainTextPassword} = req.body;
    if(!plainTextPassword || typeof plainTextPassword != 'string')
    {
        return res.json({status: 'error', error: 'invalid password'});
    }
    if(plainTextPassword.length < 8)
    {
        return res.json({status: 'error', error: 'Password field should be atleast 8 characters long'});
    }
    try{
        const user = jwt.verify(token, JWT_SECRET);
        const _id = user.id;
        const password = await bcrypt.hash(plainTextPassword, 10);
        await User.updateOne(
            {_id}, {
            $set: {password}
        });
        res.json({status: 'ok'});
    }catch(error){
        console.log(error);
        res.json({status: 'error', error: ';))'});
    }
    // console.log('JWT Decoded:', user);
    // res.json({status: 'ok'})
});


app.post('/api/login', async (req, res) => 
{
    const {username, password} = req.body;
    const user = await User.findOne({username}).lean();
    if(!user)
    {
        return res.json({status: 'error', error: 'Invalid Username/Password'});
    }
    if(await bcrypt.compare(password, user.password))
    {
        const token = jwt.sign(
            {   id: user._id, 
                username: user.username
            }, 
            JWT_SECRET
        );
        return res.json({status: 'ok', data: token});
    }

    res.json({status: 'error', error: 'Stay calm and enter the correct Username/Password !!'});
});


app.post('/api/register', async (req, res) => {
    // console.log(req.body);
    const {username, password : plainTextPassword} = req.body;
    if(!username || typeof username != 'string')
    {
        return res.json({status: 'error', error: 'invalid username'});
    }
    if(!plainTextPassword || typeof plainTextPassword != 'string')
    {
        return res.json({status: 'error', error: 'invalid password'});
    }
    if(plainTextPassword.length < 8)
    {
        return res.json({status: 'error', error: 'Password field should be atleast 8 characters long'});
    }
    const password = await bcrypt.hash(plainTextPassword, 10);
    // console.log(await bcrypt.hash(password, 10));   // 10 cycles
    try
    {
        const response = await User.create(
            {
                username, 
                password
            }
        );
        console.log("User created Successfully: ", response);
    }
    catch(error)
    {
        if(error.code == 11000)
        {
            // duplicate key
            return res.json({status : 'error', error : 'username already exists'});
        }
        throw error;
        // console.log(JSON.stringify(error));
    }
    res.json({status: 'ok'});
});


app.listen(9999, () => {
    console.log('Server up at 9999');
})