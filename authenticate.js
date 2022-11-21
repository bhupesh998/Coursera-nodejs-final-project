var passport= require('passport');
var LocalStrategy=require('passport-local').Strategy;
var User = require('./models/user');
var JwtStrategy = require('passport-jwt').Strategy;
var ExtractJwt = require('passport-jwt').ExtractJwt;
var Jwt=require('jsonwebtoken');
var config=require('./config');


exports.local=passport.use(new LocalStrategy(User.authenticate()));


passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// it will create a token and give to us
exports.getToken = user =>{
    return Jwt.sign(user,config.secretKey , {
        expiresIn : 3600
    });
}

var opts={};
// This option specifies how the jsonwebtoken should be extracted from the incoming request message. 
// This is where we will use the extract JWT
// https://stackoverflow.com/questions/36533767/nodejs-jwtstrategy-requires-a-function-to-retrieve-jwt-from-requests-error
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
// This is the second parameter which helps me to supply the secret key which
// I'm going to be using within my strategy for the sign-in
opts.secretOrKey= config.secretKey;

exports.jwtPassport = passport.use(new JwtStrategy(opts,
    (jwt_payload, done) => {
        console.log("JWT payload: ", jwt_payload);
        User.findOne({_id: jwt_payload._id}, (err, user) => {
            if (err) {
                return done(err, false);
            }
            else if (user) {
                return done(null, user);
            }
            else {
                return done(null, false);
            }
        });
    }));


// we will be using it to verify an incoming user and session false indicate we are not using session
// jwt specify the stratergy we are using 
exports.verifyUser = passport.authenticate('jwt',{session : false});