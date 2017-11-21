/* 
 custom javascript
*/

var error = getUrlParameter('error');
if(error){
	alert(error);
}

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

function getUrlParameter(sParam) {
    var sPageURL = decodeURIComponent(window.location.search.substring(1)),
        sURLVariables = sPageURL.split('&'),
        sParameterName,
        i;

    for (i = 0; i < sURLVariables.length; i++) {
        sParameterName = sURLVariables[i].split('=');

        if (sParameterName[0] === sParam) {
            return sParameterName[1] === undefined ? true : sParameterName[1];
        }
    }
};
