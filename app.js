const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");


const app = express();
app.use(express.json());
app.use(cookieParser())
const SECRET = "Ilman";
const REFRESH_SECRET = "RefreshIlman"



mongoose.connect("mongodb://127.0.0.1:27017/tokenDB");

const userSchema = new mongoose.Schema({
    username: String,
    Password: String
});

const User  = new mongoose.model("User", userSchema);

const RefreshTokenSchema = new mongoose.Schema({
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // Reference to User's ObjectId
    refresh_token: String,
    expires_at: Date
});

const RefreshToken = mongoose.model('RefreshToken', RefreshTokenSchema);


const authenticateToken = (req, res, next)=>{
    const token = req.cookies.accessToken

    if(!token) return res.sendStatus(400)

    jwt.verify(token, SECRET, (err, user)=>{
        if(err){
            res.sendStatus(401)
        }
        req.user = user;
        next()
    })
}

const generateAccessToken = (user)=>{
    return jwt.sign(user, SECRET, {expiresIn: "30m"});
}

const generateRefreshToken = (user)=>{
    return jwt.sign(user, REFRESH_SECRET, {expiresIn: "90d"});
}

const saveRefreshToken = async (userId, token)=>{
    const expiration = new Date();
    expiration.setDate(expiration.getDate() + 30);

    const refreshToken = new RefreshToken({
        user_id: userId,
        refresh_token: token,
        expires_at: expiration
    });

    await refreshToken.save();
}


app.post("/register", async (req, res)=>{
    const {username, password} = req.body;

    try{

        const userData = await User.findOne({username: username});

        if(userData){
            return res.status(400).json({Error: "User Already Exist"});
        }

        const hashPassword = await bcrypt.hash(password, 10);

        const newUser = new User({
            username: username,
            password: hashPassword
        });

        await newUser.save();

        const accessToken = generateAccessToken({user: newUser.username});
        const refreshToken = generateRefreshToken({user: newUser.username});

        await saveRefreshToken(newUser._id, refreshToken);

        res.cookie("accessToken",accessToken, {httpOnly: true, secure: true})
        res.cookie("refreshToken",refreshToken, {httpOnly: true, secure: true})
        res.json({user: newUser ,message: "logged in successfully"});


    }catch(err){
        res.status(500).json({Error: `Internal server error ${err}`});
    }

});

app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        // Check if the user exists
        const userData = await User.findOne({ username });
        if (!userData) {
            return res.status(404).json({ Error: "User does not exist" });
        }

        // Validate password
        const isPasswordValid = await bcrypt.compare(password, userData.password);
        if (!isPasswordValid) {
            return res.status(400).json({ Error: "Invalid username or password" });
        }

        // Check for a refresh token for the user
        const tokenVerification = await RefreshToken.findOne({ user_id: userData._id });
        if (!tokenVerification) {
            return res.status(400).json({ Error: "No refresh token found, please log in again" });
        }

        // Verify refresh token
        jwt.verify(tokenVerification.refresh_token, REFRESH_SECRET, (err) => {
            if (err) {
                return res.status(400).json({ Error: "Invalid refresh token" });
            }

            // Generate an access token
            const accessToken = generateAccessToken({ user: userData.username });

            // Set the access token in an HTTP-only secure cookie
            res.cookie("accessToken", accessToken, { httpOnly: true, secure: true });

            // Send a response including user information
            res.json({
                Success: "User logged in successfully",
                user: {
                    id: userData._id,
                    username: userData.username,
                    email: userData.email, // or other public fields you want to share
                },
            });
        });
    } catch (err) {
        res.status(500).json({ Error: "Internal server error during login: " + err });
    }
});


app.get("/protected", authenticateToken ,(req,res)=>{
    res.json({message:"Protected Route", user: req.user})
})



app.listen(5000, function(){
    console.log("server runnin on port 5000");
})