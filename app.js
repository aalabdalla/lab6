#!/usr/bin/node

/** */
/** Dependencies */
var express = require('express');
var http = require('http');
var bodyparser = require('body-parser');
var fs = require('fs');
var jsonfile = require('jsonfile');
var bcrypt = require('bcrypt');
var speakeasy = require('speakeasy');
var qrcode = require('qrcode');
var saltrounds = 8;

/** Stores users as JSON */
var userfile = "users.txt";

/** Initialize express.js and its templates */
var app = express();
app.use(bodyparser.urlencoded({ extended: true }));
app.set('views', './views');
app.set('view engine', 'pug');

/** Initialize the Web Server */
http.createServer(app).listen("8080", function () {
	console.log("Web Server is listening on port 8080");
});

/** Default Page
		Renders template from view/login.pug
 */
app.get('/', function(req, res) {
	res.render('login');
});

/** Checks credentials when POST to /login-check
		Parses JSON file for usernames
		Compares post data with stored data
 */
app.post('/login-check', function(req, res) {

/** Load User "database" */
	jsonfile.readFile(userfile, function(er, data) {

/** Returns filtered object.
		Should return exactly one object when username and password match an entry.
 */
		var found = data.filter(function(item) {
			return item.name == req.body.name;
		});
/** Checks if the filtered object is exactly one.
		Displays success if it is (because username and password matched)
		Displays failure if any value other than zero
 */
        bcrypt.compare(req.body.password, found[0].password, function(err, result){
            if(result){
                var usertoken = req.body.token;
                var verified = speakeasy.totp.verify({
                    secret: found[0].twofactor,
                    encoding: 'base32',
                    token: usertoken
                });
                if (verified){
                    res.send("login successful");
                    
                }else {
                    res.send("login not successful");
                }
            }else {
                res.send("login unsuccessful");   
            }
        })
		
		// check for non-existing user

	});
});

/** New user page. Renders template from views/newuser.pug */
app.get('/add-users', function(req, res) {
	res.render('newuser');
});

/** Current users page.
 		Reads userfile "database".
		Renders template from views/users.pug by passing the users object
 */
app.get('/users', function(req, res) {
	jsonfile.readFile(userfile, function(err, obj){
		if (err) throw err;
		console.log(obj);
		res.render('users', { users: obj });
	});
});

/** Add users page.
 		Reads userfile "database".
		Appends JSON object with POST data to the old userfile object.
		Writes new object to the userfile.
 */

app.post('/adduser', function(req, res) {
// storing users in file
    bcrypt.genSalt(saltrounds, function(err,salt){
        bcrypt.hash(req.body.password, salt, function(err, hash){
        var secret = speakeasy.generateSecret({length: 20 });
        var userdata = { name: req.body.name, password: hash, twofactor: secret.base32};
            
            
    qrcode.toDataURL(secret.otpauth_url, function(err, data_url){
        jsonfile.readFile(userfile, function(er, data) {
			data.push(userdata);
			jsonfile.writeFile(userfile, data, (err) => {
                res.send('successfully registered new user...<br>'
				+ '<a href="/users">Back to User List</a>'
                + '<img src= "' + data_url + '">' );
            });
		});    
    });
});
});
});
 
