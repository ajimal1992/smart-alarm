//Config
var config;
var interval;

var flag=false; //to check if firebase connection established

function startConfig(){
    config = require('./config/config');
    flag = config.FLAG;
    if (flag == true){
        clearInterval(interval);
    }
}

interval = setInterval(startConfig, 100);

function exeMain() {
    if (config.FLAG == true) { //ensure firebase exporting values completed

//DB handler
        var query = require(config.DB_HANDLER);
        query.connectSQL(config);

//Defining options for HTTPS
        var fs = require('fs');
        var HTTPSOptions = {
            key: fs.readFileSync(config.privKey),
            cert: fs.readFileSync(config.cert)
        };

		//moment
		var moment = require('moment');

//DETECTION persistance
        var last_ts = 0;

//Interval Loop to access live call
        var liveIntervalObj;

//setup plivo
        var plivo = require('plivo');
        var p = plivo.RestAPI({
            authId: config.P_AUTH,
            authToken: config.P_TOKEN
        });

//setup server - TODO: Implement HTTP(S) - ID6
        var express = require('express');
        var session = require('express-session');
        var bodyParser = require('body-parser');
        var path = require('path');
        var validator = require('validator');
        var dialog = require('dialog');
        var app = express();

//Helmet Securing
        var helmet = require('helmet');
        app.use(helmet());

        app.use(bodyParser.urlencoded({
            extended: true
        }));
        app.use(session({secret: 'secret'})); //TODO: SECURE SESSION (Configure this to solve the deprecated message) - ID7
        app.use(bodyParser.json());

//set cookie expiry
        var expiryDate = new Date(Date.now() + 60 * 60 * 1000) // 1 hour
        app.use(session({
            name: 'session',
            keys: ['key1', 'key2'], //TODO: secret key to be set
            cookie: {
                secure: true,
                httpOnly: true,
                domain: 'example.com',
                path: 'foo/bar',
                expires: expiryDate
            }
        }))

// set cookies secure true
        var cookieOptions = { expires: false};
        cookieOptions.secure = true;

//specify the resource folders
        app.use('/' + config.JS_DIR, express.static(path.join(__dirname, '/' + config.SITE_DIR + '/' + config.JS_DIR))); //app.use('/js',express.static(path.join(__dirname, '/site/js')));
        app.use('/' + config.CSS_DIR, express.static(path.join(__dirname, '/' + config.SITE_DIR + '/' + config.CSS_DIR)));


        var server = require('https').createServer(HTTPSOptions, app); //TODO: IMPLEMENT HTTPS - ID6

//Helmet Securing
        var helmet = require('helmet');
        app.use(helmet());

//OTP
        var notp = require('notp');
        var randomstring = require("randomstring");
        var OTPkey = randomstring.generate({
            length: 32
        });
        var token = '';
        var is2FAEnabled = true;


//Form Limiting
        var lock = {
            LOGIN : 0,
            OTP : 1,
            USER : 2,
            QN : 3
        };
        var lockCounts = [0,0,0,0];
        var lockTimes = [0,0,0,0];
        var lockStatus = [false, false, false, false];
        var lockRate = 3; // 3 attempts before global lockout
        var lockDelay = 15; // Lock for x seconds


// Password validation
        var passwordValidator = require('password-validator');
        var schema = new passwordValidator();
        schema
            .is().min(8)                                    // Minimum length 8
            .is().max(50)                                   // Maximum length 50
            .has().uppercase()                              // Must have uppercase letters
            .has().lowercase()                              // Must have lowercase letters
            .has().digits()                                 // Must have digits
			.has().symbols()								// Must have symbols
            .is().not().oneOf(['Password', 'Passw0rd', 'Password123']); // Blacklist these values
			
		String.prototype.isEmpty = function() {
			return (this.length === 0 || !this.trim());
		};

//start server
        server.listen(config.PORT, function () {
            console.log('Server listening at port %d', 55555);
        });


//--------------------------------------------------------------------------------------------//
//login controller 
        app.get(config.LOGIN_ROUTE, function (req, res) {
            renderView(res,config.LOGIN_FN);
        });
		
//trigger controller
        app.post('/trigger', function (req, res) {
			var row = query.get_hwID_user(req.body.hw_id);
			if(!row) //check hardware exists
				return;
				
			//check timestamp
			var formatted = moment().format('YYYY-MM-DD HH-mm-ss');
			var now = moment(formatted, 'YYYY-MM-DD HH-mm-ss');
			var ts = moment(req.body.ts, 'YYYY-MM-DD HH-mm-ss');
			var secondsDiff = ts.diff(now, 'seconds')
			if(secondsDiff<-60 || secondsDiff >0){ //1 min grace
				console.log("Denied");
				return;
			}	
			
			if(req.body.msg == config.detection_msg){
				var params = {
					'to': row[0]['dest_num'],
					'from': row[0]['src_num'],
					'answer_url': config.xmlResponse,
					'answer_method': "GET"
				};
				p.make_call(params, function (status, response) {
					liveIntervalObj = setInterval(function () {
						getLiveCall(response['request_uuid'], row[0]['msg']);
					}, 1500)
				});
			}
            
			if(req.body.msg == config.hb_msg){
				//heartbeat
				query.update_TS(req.body.hw_id,req.body.ts);
			}
        });

//timestamp controller
		app.get('/timestamp', function (req, res) {
			var formatted = moment().format('YYYY-MM-DD HH-mm-ss');
			res.send(formatted);
		});
		
//POST login controller -
        app.post(config.LOGIN_ROUTE, function (req, res) {
            req = initRequest(req);
            if (!checkLockStatusReq(lock.LOGIN, req.session.lockCounts, req.session.lockStatus, req.session.lockTimes)) { // If password lock is active,
                clearSession(req);
                res.redirect(config.LOGIN_ROUTE+"?error=Form locked due to multiple failed attempts! Please wait a moment before retrying.");
                return;
            }

            var input_un = req.body.login.user;
            var input_pw = req.body.login.pass;

            //Get ip address
            var ip = require('ip');

            ip.address() // my ip address

            //Log activity into text file
            const log4js = require('log4js');
            log4js.configure({
                appenders: {activity: {type: 'file', filename: 'activity.log'}},
                categories: {default: {appenders: ['activity'], level: 'trace'}}
            });

            const logger = log4js.getLogger('activity');

            if (query.get_user_auth(input_un, input_pw)) { //valid
                req.session.username = input_un;        // Save input username into the session

                if (is2FAEnabled) {
                    token = notp.totp.gen(OTPkey);     // Time-based OTP, default 30 seconds

                    req.session.state = config.STATE_OTP; // After successful login, advance session to the next state - OTP

                    var row = query.get_user(req.session.username);
                    var params = {
                        'src': row[0]['src_num'], // Sender's phone number with country code
                        'dst': row[0]['dest_num'], // Receiver's phone Number with country code
                        'text': "Your OTP Password is " + token + ". You have 30 seconds to enter this OTP before it expires.", // Your SMS Text Message - English
                        'url': config.xmlResponse, // The URL to which with the status of the message is sent
                        'method': "GET" // The method used to call the url
                    };

                    // Prints the complete response
                    p.send_message(params, function (status, response) {
                    });

                    res.redirect(config.OTP_ROUTE);
                }
                else {  // If 2FA is disabled, go straight to panel
                    req.session.state = config.STATE_PANEL;
                    res.redirect(config.PANEL_ROUTE);
                }
                logger.trace(req.body.login.user + ' successful login from ' + ip.address());
            }
            else { //user not found
                incLockCountReq(lock.LOGIN, req.session.lockCounts, req.session.lockStatus, req.session.lockTimes);
                clearSession(req);
                res.redirect(config.LOGIN_ROUTE+"?error=Incorrect login parameters!");
                logger.trace(req.body.login.user + ' unsuccessful login from ' + ip.address());
            }
        });
//--------------------------------------------------------------------------------------------//
//Controller for OTP
        app.get(config.OTP_ROUTE, function (req, res) {
            if (req.session.state == config.STATE_OTP && is2FAEnabled == true) {
                renderView(res, config.OTP_FN);
            }
            else {
                clearSession(req);
                res.redirect(config.LOGIN_ROUTE);
            }
        });

//POST OTP controller, queries for OTP
        app.post(config.OTP_VERIFY_ROUTE, function (req, res) {
            if (req.session.state == config.STATE_OTP && is2FAEnabled == true) {
                if (!checkLockStatusReq(lock.OTP, req.session.lockCounts, req.session.lockStatus, req.session.lockTimes)) { // If password lock is active,
                    clearSession(req);
                    res.redirect(config.LOGIN_ROUTE+"?error=Form locked due to multiple failed attempts! Please wait a moment before retrying.");
                    return;
                }

                var input_token = req.body.otp.token;

                if (notp.totp.verify(input_token, OTPkey)) { // Token matched
                    req.session.state = config.STATE_PANEL; // Advance session to the next stage - security questions
                    res.redirect(config.PANEL_ROUTE); // Redirects user to input security questions
                }
                else { // Token not matched
                    incLockCountReq(lock.OTP, req.session.lockCounts, req.session.lockStatus, req.session.lockTimes);
                    res.redirect(config.OTP_ROUTE+"?error=Incorrect OTP!");
                }
            }
            else {
                clearSession(req);
                res.redirect(config.LOGIN_ROUTE);
            }
        });

//POST OTP controller, requests another OTP
        app.post(config.OTP_REQUEST_ROUTE, function (req, res) {
            if (req.session.state == config.STATE_OTP && is2FAEnabled == true) {

                var prevToken = token;
                token = notp.totp.gen(OTPkey);     // Time-based OTP, default 30 seconds

                if (token != prevToken) {   // Only when time for current token expires, send another
                    var row = query.get_user(req.session.username);
                    var params = {
                        'src': row[0]['src_num'], // Sender's phone number with country code
                        'dst': row[0]['dest_num'], // Receiver's phone Number with country code
                        'text': "Your OTP Password is " + token + ". You have 30 seconds to enter this OTP before it expires.", // Your SMS Text Message - English
                        'url': config.xmlResponse, // The URL to which with the status of the message is sent
                        'method': "GET" // The method used to call the url
                    };

                    p.send_message(params, function (status, response) {
                    });
					res.redirect(config.OTP_ROUTE+"?error=Another OTP has been requested!");
                }
				else {
					res.redirect(config.OTP_ROUTE+"?error=Please wait a moment to request another OTP!");
				}
            }
            else {
                clearSession(req);
                res.redirect(config.LOGIN_ROUTE);
            }
        });

//--------------------------------------------------------------------------------------------//
//Reset controller for username
        app.get(config.RESET_ROUTE, function (req, res) {
            renderView(res, config.RESET_FN);
        });

//POST Reset controller, queries for username
        app.post(config.RESET_ROUTE, function (req, res) {
            req = initRequest(req);
            if (!checkLockStatusReq(lock.USER, req.session.lockCounts, req.session.lockStatus, req.session.lockTimes)) { // If password lock is active,
                clearSession(req);
                res.redirect(config.LOGIN_ROUTE+"?error=Form locked due to multiple failed attempts! Please wait a moment before retrying.");
                return;
            }

            var user = req.body.reset.user;
			req.session.username = user; // Stores the username in the cookie

			if (!user.isEmpty()) {
				if (query.get_username(user)) { // Is there such a user?
					req.session.state = config.STATE_RESET_QN; // Advance session to the next stage - security questions
					req.session.username = user; // Stores the username in the cookie
					res.redirect(config.RESET_QN_ROUTE); // Redirects user to input security questions
				}
				else { //user not found
					incLockCountReq(lock.USER, req.session.lockCounts, req.session.lockStatus, req.session.lockTimes);
					clearSession(req);
					res.redirect(config.RESET_ROUTE+"?error=Incorrect username!");
				}
			}
			else {
				incLockCountReq(lock.USER, req.session.lockCounts, req.session.lockStatus, req.session.lockTimes);
				clearSession(req);
				res.redirect(config.RESET_ROUTE+"?error=Incorrect username!");
			}
        });
//--------------------------------------------------------------------------------------------//
//Reset security questions controller
        app.get(config.RESET_QN_ROUTE, function (req, res) {
            if (req.session.state == config.STATE_RESET_QN) {
                renderView(res, config.RESET_QN_FN);
            }
            else {
                clearSession(req);
                res.redirect(config.LOGIN_ROUTE);
            }
        });

//POST Reset security questions controller
        app.post(config.RESET_QN_ROUTE, function (req, res) {
            if (req.session.state == config.STATE_RESET_QN) {    // Requires going through username check first
                if (!checkLockStatusReq(lock.QN, req.session.lockCounts, req.session.lockStatus, req.session.lockTimes)) { // If password lock is active,
                    clearSession(req);
                    res.redirect(config.LOGIN_ROUTE+"?error=Form locked due to multiple failed attempts! Please wait a moment before retrying.");
                    return;
                }

                var username = req.session.username;
                var q1 = req.body.reset.q1;
                var q2 = req.body.reset.q2;
				
				if (!q1.isEmpty() && !q2.isEmpty()) {
					if (query.auth_answers(q1, q2, username)) {
						req.session.state = config.STATE_RESET_PW; // Move session to the next state - Password
						res.redirect(config.RESET_PW_ROUTE);
					}
					else { // user not found
						incLockCountReq(lock.QN, req.session.lockCounts, req.session.lockStatus, req.session.lockTimes);
						res.redirect(config.RESET_QN_ROUTE+"?error=Incorrect password!"); // Retry if wrong answers
					}
				} 
				else {
					incLockCountReq(lock.QN, req.session.lockCounts, req.session.lockStatus, req.session.lockTimes);
					res.redirect(config.RESET_QN_ROUTE+"?error=Incorrect password!"); // Retry if wrong answers
				}
            }
            else { // Not in the right session state
                clearSession(req);
                res.redirect(config.LOGIN_ROUTE); // Redirect if no session
            }
        });
//--------------------------------------------------------------------------------------------//
//Reset password controller
        app.get(config.RESET_PW_ROUTE, function (req, res) {
            if (req.session.state == config.STATE_RESET_PW) {
                renderView(res, config.RESET_PW_FN);
            }
            else {
                clearSession(req);
                res.redirect(config.LOGIN_ROUTE);
            }
        });

//POST Reset Password controller
        app.post(config.RESET_PW_ROUTE, function (req, res) {
            if (req.session.state == config.STATE_RESET_PW) {    // Requires going through sec qn check first
                var pw = req.body.reset.pass;
				
                if (schema.validate(pw) && !pw.isEmpty()) {
                    query.update_password(pw, req.session.username);
                    clearSession(req);  // Clears the session
                    res.redirect(config.LOGIN_ROUTE+"?error=Password resetted successfully! Please login with your new password.");
                }
                else { // Password does not conform to specifications.
                    res.redirect(config.RESET_PW_ROUTE+"?error=Password does not meet requirements!"); // Retry if invalid password
                }
            }
            else {
                clearSession(req);
                res.redirect(config.LOGIN_ROUTE); // Redirect if no session
            }
        });
		
//POST panel controller reset security question
        app.post(config.PANEL_RESET_ROUTE, function (req, res) {
            if (req.session.state == config.STATE_PANEL) {
                var sa1 = req.body.securityAns.ansOne;
                var sa2 = req.body.securityAns.ansTwo;
				var sq1 = req.body.securityOne;
				var sq2 = req.body.securityTwo;
				
				if (!sa1.isEmpty() && !sa2.isEmpty()) {
					query.update_security(sq1, sq2, sa1, sa2, req.session.username);
					res.redirect(config.PANEL_ROUTE+"?error=Security questions changed sucessfully!");
				} 
				else {
					res.redirect(config.PANEL_ROUTE+"?error=Invalid answers!");
				}
            }
            else {
                clearSession(req);
                res.redirect(config.LOGIN_ROUTE);
            }
        });

//--------------------------------------------------------------------------------------------//
//panel controller - TODO?: SECURE PANEL
        app.get(config.PANEL_ROUTE, function (req, res) {
            if (req.session.state == config.STATE_PANEL) {
                renderView(res, config.PANEL_FN);
            }
            else {
                clearSession(req);
                res.redirect(config.LOGIN_ROUTE);
            }
        });


//POST panel controller - TODO: Validate and update configuration inputs received from user - ID9
        app.post(config.PANEL_ROUTE, function (req, res) {
            if (req.session.state == config.STATE_PANEL) {
                var src = req.body.panel.src;
                var dest = req.body.panel.dest;
                var addr = req.body.panel.addr;
                var intro = req.body.panel.intro;

                if (!validator.isNumeric(src) || !validator.isNumeric(dest)) {
					res.redirect(config.PANEL_ROUTE+"?error=Please enter numeric values!");
                }
                else { // validated
                    query.update_user_profile(addr, src, dest, intro, req.session.username);
                    res.redirect(config.PANEL_ROUTE);
                }
            }
            else {
                clearSession(req);
                res.redirect(config.LOGIN_ROUTE);
            }
        });

//POST panel controller reset password
        app.post(config.PWD_ROUTE, function (req, res) {
            if (req.session.state == config.STATE_PANEL) {
				var oldPwd = req.body.resetPass.oldPass;
                var newPwd = req.body.resetPass.newPass;
                var confirmPwd = req.body.resetPass.confirmPass;

				if (query.get_user_auth(req.session.username, oldPwd)) {
					if (newPwd != confirmPwd) {
						res.redirect(config.PANEL_ROUTE+"?error=Passwords are not the same!");
					} 
					else { //validated
						 if (schema.validate(newPwd) && !newPwd.isEmpty()) {
							query.update_password(confirmPwd, req.session.username);
							res.redirect(config.PANEL_ROUTE+"?error=Password changed sucessfully!");
						 }
						 else {
							res.redirect(config.PANEL_ROUTE+"?error=Password does not match requirements.");
						 }
					}
				} else {
					res.redirect(config.PANEL_ROUTE+"?error=Enter your current password!");
				}
				
            }
            else {
                clearSession(req);
                res.redirect(config.LOGIN_ROUTE);
            }
        });

//POST panel controller logout
        app.post(config.LOGOUT_ROUTE, function (req, res) {
            clearSession(req);
            res.redirect(config.LOGIN_ROUTE);
        });

//--------------------------------------------------------------------------------------------//

//config controller - 
        app.get(config.USRCONFIG_ROUTE, function (req, res) {
            if (req.session.state == config.STATE_PANEL) {
                var row = query.get_user(req.session.username);
                var JSON = {
                    'addr': row[0]['address'],
                    'src': row[0]['src_num'],
                    'dest': row[0]['dest_num'],
                    'intro': row[0]['msg']
                };
                res.send(JSON);
            } else if (req.session.state == config.STATE_RESET_QN) {
				var row = query.get_userQ(req.session.username);
                var JSON = {
                    'sq1': row[0]['sec_q1'],
                    'sq2': row[0]['sec_q2'],
					'q1': row[0]['sec_ans1'],
                    'q2': row[0]['sec_ans2']
                };
                res.send(JSON);
			}
            else
                res.redirect(config.LOGIN_ROUTE);
        });

        function renderView(res, htmlFile) {
            res.sendFile(path.join(__dirname + '/' + config.SITE_DIR + '/' + htmlFile));
        }


        function getLiveCall(UUID, intro) {
            var parameter = {'call_uuid': UUID, 'text': intro, 'language': 'en-GB'};
            p.speak(parameter, function (status, response) {
                if (status != 404) {
                    clearInterval(liveIntervalObj);
                }
            });
        }

        function initRequest(req) {
            if (!req.session.isSessionInit) {
                req.session.lockCounts = lockCounts.slice(0);
                req.session.lockTimes = lockTimes.slice(0);
                req.session.lockStatus = lockStatus.slice(0);
                req.session.isSessionInit = true;
            }
            return req;
        }

        function checkLockStatusReq(index, count, status, times) {
            if (status[index]) {
                var locktime = times[index];
                if (checkLockTimesReq(locktime)) { // 5 seconds
                    // Release lock
                    status[index] = false;
                    count[index] = 0;
                    return true;
                }
                else {
                    return false;
                }
            }
            return true;
        }

        function checkLockTimesReq(time) {
            var currentTime = new Date();
            var lockTime = new Date(time);
            currentTime = (currentTime.getTime() - lockTime.getTime()) / 1000;
            if (currentTime > lockDelay) { // X seconds
                return true;
            }
            else {
                return false;
            }
        }

        function incLockCountReq(index, counts, status, times) {
            counts[index] = counts[index] + 1;
            //Count increased
            if (counts[index] >= lockRate) {
                //Lock activated
                status[index] = true;
                times[index] = new Date();
            }
        }

        function clearSession(req) {
            req.session.username = null;
            req.session.state = null;
        }
		
		//initialize captcha
		reCAPTCHA=require('recaptcha2')

		recaptcha=new reCAPTCHA({
		  siteKey: config.CAPTCHA_SITEKEY,
		  secretKey: config.CAPTCHA_SECRETKEY
		})

		//verify captcha key
		function submitForm(req,res){
		  recaptcha.validateRequest(req)
		  .then(function(){
			// validated and secure
			res.json({formSubmit:true})
		  })
		  .catch(function(errorCodes){
			// invalid
			res.json({formSubmit:false,errors:recaptcha.translateErrors(errorCodes)});// translate error codes to human readable text
		  });
		}

//check heartbeat
var hb_interval = setInterval(function () {
					var dump = query.check_TS();
					for(var i=0; i<dump.length; i++){
						var row = dump[i];
						var formatted = moment().format('YYYY-MM-DD HH-mm-ss');
						var now = moment(formatted, 'YYYY-MM-DD HH-mm-ss');
						var ts = moment(row['timestamp'], 'YYYY-MM-DD HH-mm-ss');
						var secondsDiff = ts.diff(now, 'seconds')
						if(secondsDiff<=-120 || secondsDiff >0){ //1 min grace
							query.update_check(row['username']);
							console.log("hw lost");
							
							var params = {
								'src': row['src_num'], // Sender's phone number with country code
								'dst': row['dest_num'], // Receiver's phone Number with country code
								'text': "Your alarm service has lost connection. Please contact admin support.", // Your SMS Text Message - English
								'url': config.xmlResponse, // The URL to which with the status of the message is sent
								'method': "GET" // The method used to call the url
							};

							p.send_message(params, function (status, response) {
							});
						}	
					}
				}, 1000*60*2); //check every 2 mins

//-------------------------------------------------------------------------------
		clearInterval(executeMain); //break off from the main execution time loop
	} //end of if
}

var executeMain;
executeMain = setInterval(exeMain, 100); //set timer to get the Firebase Connection up then exec it

