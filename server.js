require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
var passport = require('passport');
var LocalStrategy = require('passport-local');
var crypto = require('crypto');
const bcrypt = require('bcrypt');
const saltRounds = 10;
var logger = require('morgan');
var session = require('express-session');
//ar SQLiteStore = require('connect-sqlite3')(session);
var GoogleStrategy = require('passport-google-oauth20').Strategy;
const otpGenerator = require('otp-generator');


var nodemailer = require('nodemailer');

var transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'garvsoni2912@gmail.com',
    pass: process.env.PASS
  }
});



const app = express();
app.use(express.static("public"));
//app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'MereBaba,BabaMere',
  resave: false,
  saveUninitialized: false,
  //store: new SQLiteStore({ db: 'sessions.db', dir: './var/db' })
}));
app.use(passport.authenticate('session'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
  }));
  const userSchema4 = new mongoose.Schema ({
    dept: String,
    AKey:String
  });
  const Admin = new mongoose.model("Admin", userSchema4);  
  const userSchema3 = new mongoose.Schema ({
    name: String
  });
  const crop = new mongoose.model("crop", userSchema3);  

const userSchema = new mongoose.Schema ({
    name:String,
    Reg:String,
    State:String,
    District:String,
    Program:String,
    Add:String,
    DOR:Date,
    RInst:String,
    email: String,
    mobile: String,
    password: String,
    crops: [{
        type: Schema.Types.ObjectId,
        ref: 'crop'
     }]
  });
const FPO = new mongoose.model("FPO", userSchema);  

const userSchema2 = new mongoose.Schema ({
    email: String,
    mobile: String,
    password: String,
    googleId: String,
    paid: Boolean
  });
const User = new mongoose.model("User", userSchema2);  

var GS = "";                           //******************************************************** //*//

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/callback"
    //userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  async function(accessToken, refreshToken, profile, cb) {
   // console.log(profile);
    
   var user=await User.find({ googleId: profile.id });
   if (user.length===0){
      User.insertMany({googleId: profile.id});
   }
   user=await User.find({ googleId: profile.id });
   GS= user.email;         /////////////////////////////
   
   return cb(null,user);
   
  }
));


passport.use(new LocalStrategy(async function verify(username, password, cb) {
//     db.get('SELECT * FROM users WHERE username = ?', [ username ], function(err, row) {
//       if (err) { return cb(err); }
//       if (!row) { return cb(null, false, { message: 'Incorrect username or password.' }); }
  
   const row= await User.find({email: username});
  
   if(row.length===0){
    return cb(null, false, { message: 'Incorrect username or password.' });
   }
    // crypto.pbkdf2(password, row.salt, 310000, 32, 'sha256', function(err, hashedPassword) {
    //     if (err) { return cb(err); }
    //     if (!crypto.timingSafeEqual(row.hashed_password, hashedPassword)) {
    //       return cb(null, false, { message: 'Incorrect username or password.' });
    //     }
    //     return cb(null, row);
    //   });
    // });
    GS = username;
    
    bcrypt.compare(password, row[0].password, function(err, result) {
        if(result===true){
            
          if(row[0].paid){
          
            return cb(null, row);
            //return;
          }else{
            return cb(null, row);
          }
            
        }else{
            return cb(null, false, { message: 'Incorrect username or password.' });
        }
        });


}));  

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user._id, username: user.username });
    });
  });
  
passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });


 
  

mongoose.connect('// my personal mongo db cloud database url, cant expose here// ').then(console.log("Mere Baba"));


app.get("/auth/google",
  passport.authenticate("google", { scope: ['profile'] }));

app.get("/auth/google/callback", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    console.log("callback");
    res.redirect("/homepage2");
  });


app.get("/",function(req,res){
    res.render("home");
});

app.get("/FPO",function(req,res){
    res.render("FPO");
});

app.get("/consumer",function(req,res){
    res.render("homepage1");
});

app.get("/Admin",function(req,res){
    res.render("Admin");
});

app.get("/profile", async function(req,res){
  const f = await FPO.find({});
  res.render(profile,{ fpo:f});
});

app.get("/analytics",function(req,res){
    res.render("analytics");
});

app.post("/A/login/password", async function(req,res){
    const adm= await User.find({dept: req.body.username});
    if(adm.length===0){
        res.redirect("/Admin");
       }
      
        
        
        bcrypt.compare(req.body.password, adm[0].AKey, function(err, result) {
            if(result===true){
                
            res.render("Ahome");
                
            }else{
                res.redirect("/Admin");
            }
            });
    
    
    });  


  app.post("/search", async function(req,res){
        const f = await FPO.find({district:req.body.district,State:req.body.State,Reg:req.body.Reg});
        res.render(profile,{ fpo:f});
        
        
        });  




    

