/* 
JavaScript for displaying error messages
*/

var error = getUrlParameter('error');

if(error){	
	var UrlNoParams = window.location.href.replace(window.location.search,'');
	location.replace(UrlNoParams); // Reset the URL for visibility purposes and prevent alert on refresh.
	alert(error);
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
