//crypto
var crypto = require('crypto');

//setup sqlite
var sqlite = require('sqlite-cipher');

exports.connectSQL = function(config){
  sqlite.connect(config.DB_FN,config.DB_SECRET,config.DB_ALGO);
};

exports.dumpData = function(){
  console.log(sqlite.run("SELECT * FROM profile_info"));
};

exports.get_hwID_user = function(hw_id){
  return sqlite.run("SELECT address, src_num, dest_num, msg FROM profile_info WHERE hw_id = ?",[hw_id]);
}

exports.get_user = function(username){
  return sqlite.run("SELECT address, src_num, dest_num, msg FROM profile_info WHERE username = ?",[username]);
}

exports.get_userQ = function(username){
  return sqlite.run("SELECT sec_q1, sec_q2, sec_ans1, sec_ans2 FROM profile_info WHERE username = ?",[username]);
}

exports.get_pwd = function(username){
  return sqlite.run("SELECT password, salt FROM profile_info WHERE username = ?",[username]);
}

exports.get_user_auth = function(username,password){
  var row = sqlite.run("SELECT username,password,salt FROM profile_info WHERE username = ?",[username]);
  if(row.length == 1){ //username found
    var pw_hash = sha512(password, row[0]['salt']);
    if(row[0]['password'] == pw_hash) //valid pass
      return true;
    else //invalid pass
      return false;
	}
	else //user not found
		return false;
}

exports.get_username = function(username) { // Finds if username is in db
    var row = sqlite.run("SELECT username FROM profile_info WHERE username = ?",[username]);
    if(row.length == 1) //username found
        return true;
    else //user not found
        return false;
}

exports.get_sec_qns = function(username, index) { // Finds if username is in db
    var row = sqlite.run("SELECT sec_qn1, sec_qn2 FROM profile_info WHERE username = ?",[username]);

    if(row.length == 1) //username found
        if (index == 1)
            return row[0]['sec_qn1'];
        else
            return row[0]['sec_qn2']
    else //user not found
        return false;
}

exports.auth_answers = function(a1,a2,username) {
    var row = sqlite.run("SELECT sec_ans1, sec_ans2 FROM profile_info WHERE username = ?", [username]);
    if (row.length == 1) {//username found
        if (a1 == row[0]["sec_ans1"] && a2 == row[0]["sec_ans2"])
            return true;
        else //user not found
            return false;
    }
    else {
        console.log(row.length);
        return false;
    }
}

exports.update_security = function(qnsOne,qnsTwo,ansOne,ansTwo,username){
  sqlite.run('UPDATE profile_info SET sec_q1 = ?, sec_q2 = ?, sec_ans1 = ?, sec_ans2 = ? WHERE username = ?', [qnsOne,qnsTwo,ansOne,ansTwo,username]);
}

exports.update_user_profile = function(addr,src,dest,intro,username){
  sqlite.run('UPDATE profile_info SET address = ?, src_num = ?, dest_num = ?, msg = ? WHERE username = ?', [addr,src,dest,intro,username]);
}

exports.update_password = function(pass,username){
    var salt = genRandomString(16);
    var pw_hash = sha512(pass, salt);
    sqlite.run('UPDATE profile_info SET password = ?, salt = ? WHERE username = ?', [pw_hash,salt,username]);
}


// Placeholder function to add in columns for security questions and answers.
exports.alter_db_table = function() {
    //console.log(sqlite.run("ALTER TABLE profile_info ADD timestamp TEXT"));
	//console.log(sqlite.run("ALTER TABLE profile_info ADD checked int"));
	//console.log(sqlite.run("UPDATE profile_info SET timestamp = '2017-11-11 17-25-46', checked = 0"));
    //sqlite.run("ALTER TABLE profile_info ADD sec_q2 TEXT");
    //sqlite.run("ALTER TABLE profile_info ADD sec_ans1 TEXT");
    //sqlite.run("ALTER TABLE profile_info ADD sec_ans2 TEXT");
    //sqlite.run("UPDATE profile_info SET sec_q1 = ?, sec_q2 = ?, sec_ans1 = ?, sec_ans2 = ? WHERE username = 'ict3x03'",
    //    ["What is the first answer", "What is the second answer", "ans1", "ans2"]);
}

exports.update_TS = function(hw_id,ts){
	sqlite.run('UPDATE profile_info SET timestamp = ?, checked = 0 WHERE hw_id = ?',[ts,hw_id]);
}

exports.update_check = function(username){
	sqlite.run('UPDATE profile_info SET checked = 1 WHERE username = ?',[username]);
}

exports.check_TS = function(){
	return sqlite.run("SELECT timestamp, src_num, dest_num, checked, username FROM profile_info WHERE checked!=1");
}

sha512 = function(password, salt){
  var hash = crypto.createHmac('sha512', salt); /** Hashing algorithm sha512 */
  hash.update(password);
  var value = hash.digest('hex');
  return value;
}

genRandomString = function(length){
    return crypto.randomBytes(Math.ceil(length/2))
        .toString('hex') /** convert to hexadecimal format */
        .slice(0,length);   /** return required number of characters */
};