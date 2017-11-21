
// **Initial load may fail as export need time to poll again. Initail load is empty
//Variable Declaration

var flag=false; // flag to ensure ref.on run complete first
//-------------------------------------------------------------------------------------------
//Firebase local variables
//variable to store login values from firebase
//Filenames
var login; 
var panel;
var reset;
var reset_qn;
var reset_pw;
var site_d;
var js_d;
var css_d;
var certificate;
var privatekey;

// Cookie States Variables (s = state)
var s_login;
var s_panel;
var s_resetQn;
var s_resetPw;
var s_reset_U;

// Port Variables
var serverPort;

// Route Variables (r = route)
var r_resetPW;
var r_resetQn;
var r_reset;
var r_login;
var r_logout;
var r_pwd;
var r_sQns;
var r_panel;
var r_usrconfig;

//Com Port Variables
var v_com_port;
var v_baud_rate;

// Detection Variables
var v_delay_minute;
var v_detection_msg;
var v_hb_msg;

// XML Cloud Variable
var v_xmlResponse;

//API KEY Variables
var v_p_auth;
var v_p_token;

// DB Variables
var v_db_fn;
var v_db_secret;
var v_db_algo;
var v_db_handler;

var testing;

//Recaptcha Variables
var v_sitekey;
var v_secretkey;
//-------------------------------------------------------------------------------------------
var db;
var ref;
var configInterval;

//Firebase Implementation
//Firebase Connection
var firebase = require("firebase-admin");
var serviceAccount = require('../db/firedetectionsystemservice.json')

firebase.initializeApp({
    credential: firebase.credential.cert(serviceAccount),
    // may need to protect this string
    databaseURL: "https://firedetectionsystem-484d2.firebaseio.com/"
});

db = firebase.database();
ref = db.ref();

ref.on("value", function(snap){
    //GET firebase values to local
    login = snap.val().login;
    otp = snap.val().otp;
    panel = snap.val().panel;
    reset = snap.val().reset;
    reset_qn = snap.val().reset_qn_fn;
    reset_pw = snap.val().reset_pw_fn;
    site_d = snap.val().site_dr;
    js_d = snap.val().js_dir;
    css_d = snap.val().css_dir;
    certificate = snap.val().cert;
    privatekey = snap.val().privKey;
   
    s_login = snap.val().state_login;
    s_otp = snap.val().state_otp;
    s_panel = snap.val().state_panel;
    s_resetQn = snap.val().state_reset_qn;
    s_resetPw = snap.val().state_reset_pw;
    s_reset_U = snap.val().state_reset_user;
   
    serverPort = snap.val().port;
  
    r_login = snap.val().login_route;
    r_logout = snap.val().logout_route;
    r_otp = snap.val().otp_route;
    r_otp_verify = snap.val().otp_verify_route;
    r_otp_request = snap.val().otp_request_route;
    r_reset = snap.val().reset_route;
    r_resetQn = snap.val().reset_qn_route;
    r_resetPW = snap.val().reset_pw_route;
    r_panel = snap.val().panel_route;
    r_usrconfig = snap.val().usrconfig_route;
    r_pwd = snap.val().pwd_route;
	r_sQns = snap.val().panel_reset_route;
  
    v_com_port = snap.val().com_port;
    v_baud_rate = snap.val().baud_rate;
    v_delay_minute = snap.val().delay_minute;
	v_hb_msg = snap.val().hb_msg;
    v_detection_msg = snap.val().detection_msg;
    v_xmlResponse = snap.val().xmlResponse;
    v_p_auth = snap.val().p_auth;
    v_p_token = snap.val().p_token;
    v_db_fn = snap.val().db_fn;
    v_db_secret = snap.val().db_secret;
    v_db_algo = snap.val().db_algo;
    v_db_handler = snap.val().db_handler;

    v_sitekey = snap.val().captcha_sitekey;
    v_secretkey = snap.val().captcha_secretkey;

    exports.FLAG = true; //trigger server.js to execute main

    flag = true;
    ;
});

//-------------------------------------------------------------------------------

function ExportValue(){

    if (flag == true){
//filenames
        exports.LOGIN_FN = login;
        exports.OTP_FN = otp;
        exports.PANEL_FN = panel;
        exports.RESET_FN = reset;
        exports.RESET_QN_FN = reset_qn;
        exports.RESET_PW_FN = reset_pw;
        exports.SITE_DIR = site_d;
        exports.JS_DIR = js_d;
        exports.CSS_DIR = css_d;

        exports.cert = certificate;
        exports.privKey = privatekey;

// Cookie States
        exports.STATE_LOGIN = s_login;
        exports.STATE_OTP = s_otp;
        exports.STATE_RESET_USER = s_reset_U;
        exports.STATE_RESET_QN = s_resetQn;
        exports.STATE_RESET_PW = s_resetPw;
        exports.STATE_PANEL = s_panel;

//Port
        exports.PORT = serverPort;

//URL routes
        exports.LOGIN_ROUTE = r_login;
        exports.OTP_ROUTE = r_otp;
        exports.OTP_VERIFY_ROUTE = r_otp_verify;
        exports.OTP_REQUEST_ROUTE = r_otp_request;
        exports.LOGOUT_ROUTE = r_logout;
        exports.PANEL_ROUTE = r_panel;
        exports.PWD_ROUTE = r_pwd;
		exports.PANEL_RESET_ROUTE = r_sQns;
        exports.RESET_ROUTE = r_reset;
        exports.RESET_QN_ROUTE = r_resetQn;
        exports.RESET_PW_ROUTE = r_resetPW;
        exports.USRCONFIG_ROUTE = r_usrconfig; //TODO?: I DONT KNOW IF HAVING A ROUTE JUST TO RETRIEVE SENSITIVE DATA IS A BAD IDEA. Need more research.

//COM PORT
        exports.COM_PORT = v_com_port; //Allow user to set serial port in the control panel - ID1
        exports.BAUD_RATE = v_baud_rate;

//Detection
        exports.delay_minute = v_delay_minute; //TODO: custom Delay Detection- ID4
        exports.detection_msg = v_detection_msg;
		exports.hb_msg = v_hb_msg;

//XML cloud
        exports.xmlResponse = v_xmlResponse; //TODO: Custom Message - ID3

//API KEY
        exports.P_AUTH = v_p_auth;
        exports.P_TOKEN = v_p_token;

//DB
        exports.DB_FN = v_db_fn;
        exports.DB_SECRET = v_db_secret;
        exports.DB_ALGO = v_db_algo;
        exports.DB_HANDLER = v_db_handler;

        //recaptcha
        exports.CAPTCHA_SITEKEY = v_sitekey;
        exports.CAPTCHA_SECRETKEY = v_secretkey; 

        clearInterval(configInterval);
    } //end if
}

configInterval = setInterval(ExportValue, 100);