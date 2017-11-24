/* 
 custom javascript
*/

function getSecurityQuestion(){
	$.get('/config', {}, function(data){
		$('#sq1').val(data['sq1']);
		$('#sq2').val(data['sq2']);
	});
}

function getUserData(){ //TODO: I DONT KNOW IF HAVING A ROUTE JUST TO RETRIEVE SENSITIVE DATA IS A BAD IDEA. Need more research.
	$.get('/config', {}, function(data){
		$('#src').val(data['src']);
		$('#dest').val(data['dest']);
		$('#intro').val(data['intro']);
		$('#addr').val(data['addr']);
	});
}
