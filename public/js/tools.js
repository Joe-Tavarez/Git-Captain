var gitPortEndPoint = '', // Will be set from server configuration
    oAuthToken,
    repoCount = 0,
    logNumber = 0,
    repoCountForDelete = 0,
    repoCountForSearch = 0,
    repoCountForPRSearch = 0,
    clientID = '',
    orgName = '',
    timeOutInMinutes = 30, //set to default of 30 minutes, but overridden by server call.
    authCode;

var arrayOfRepos = [];

var modalSpinner,
    selectionOne,
    selectionTwo;


function getUserName() {
    var token = oAuthToken.replace("access_token=", "").replace("&scope=repo&token_type=bearer", "");
    
    makeCall(
        getUserNameResponse,
        "https://api.github.com/user",
        "GET",
        null,
        token
    );
}

// Constructor function for repo object
function repoObject(name, full_name) {
    this.name = name;
    this.full_name = full_name;
}

function getUserNameResponse(data) {
    showProfile(data);
    populateArrayOfRepos();//arrayOfRepos

}

function initJquerySelectors(htmlFile) {
    if (htmlFile === 'authenticated') {
        selectionOne = $('li[data="client"]');
        selectionTwo = $('li[data="server"]');
    }
    modalSpinner = $('#modalSpinner');
}

function populateArrayOfRepos() { //populateList(repoSetServer, "server");
    showSpinner();

    function callback(data) {
        if (data.statusCode === 200) {
            var reposList = JSON.parse(data.body);

            for (var i = 0; i < reposList.length; i++) {
                // noinspection JSUnresolvedVariable
                arrayOfRepos.push(new repoObject(reposList[i].name, reposList[i].full_name));
            }

            populateList(arrayOfRepos);
        }

        else {

            var r = confirm("Error retreiving your repos. Press OK to try again or CANCEL to logoff.");
            if (r) {
                populateArrayOfRepos();
            }
            else {
                logOff();
            }

        }
        hideSpinner();
    }

    var cleanToken = oAuthToken.replace("access_token=", "").replace("&scope=repo&token_type=bearer", "");
    var params =
        {
            token: cleanToken
        };

    makeCall(callback, './gitCaptain/searchForRepos', 'POST', params)

}


/*** start login/logout functions ***/
function showProfile(json) {

    var apiDataDiv = $('#apiData');
    apiDataDiv.html('<div id="loader"><img src="/static/css/loader.gif" alt="loading..."></div>');

    if (json === null) {
        logOff();
        alert("An error occurred when login in. Please login again!");
    }
    else {
        // noinspection JSUnresolvedVariable
        var fullName = json.name,
            userName = json.login,
            avatarURL = json.avatar_url,
            profileURL = json.html_url;

        if (fullName === undefined || fullName === null) {
            fullName = userName;
        }

        var outHTML = '<p style="display:inline-block; vertical-align:top; margin-left:10px;">' + fullName + '</p>';
        outHTML = outHTML + '<div class="ghcontent" style="display: inline-block;"><div class="avi"><a href="' + profileURL + '" target="_blank"><img src="' + avatarURL + '" width="40" height="40" alt="' + userName + '"></a></div>';
        outHTML = outHTML + '</div> <button onclick="logOff();" id="clearLogButton" style="float:right; margin-right:10px;"" type="submit" class="btn btn-danger" data-disable-invalid="" data-disable-with="">Sign Out</button>';

        apiDataDiv.html(outHTML);
    }
}

function checkGitHubStatus() {
    showSpinner();

    function callback(data) {
        if (data.statusCode === 200) {
            var serverInfo = JSON.parse(data.body);
            if (serverInfo.status === 'good') {
                //do nothing everything is fine. Purposefully kept for future use.
                hideSpinner();
            }
            else { //GitHub is NOT 'good' status, thus inform the users.
                $("#loginHeader").text('Git-Captain is currently down!');
                $("#loginInfo").text('GitHub is currently experiencing issues. GitHub states: ' + serverInfo.body);
                $("#getUserAuth").hide();
                hideSpinner();
            }
        }
    }

    makeCall(callback, './gitCaptain/checkGitHubStatus', 'GET')
}

function isGitCaptainUp(isLoginScreen) {
    function callback(data) {
        if (data.statusCode === 200) {
            if (data.status === 'up') {
                clientID = data.clientID;
                orgName = data.orgName;
                timeOutInMinutes = data.clientTimeout;
                gitPortEndPoint = data.gitPortEndPoint; // Set from server configuration
                if (isLoginScreen) {
                    checkGitHubStatus();
                }
                else {
                    setTimeoutTimer();
                }
            }
            else { //GitHub is NOT 'good' status, thus inform the users.
                $("#loginHeader").text('Git-Captain is currently down!');
                $("#loginInfo").text(data.reason);
                $("#getUserAuth").hide();
                hideSpinner();
            }
        }
        hideSpinner();
    }

    makeCall(callback, './gitCaptain/checkGitCaptainStatus', 'GET')
}

function logOff(isTimedOut) {
    showSpinner();

    function callback() {
        if (isTimedOut) {
            window.location.href = window.location.origin + "/?isTimedOut=true";
        }
        else {
            window.location.href = window.location.origin + "/?isLogOff=true";
        }
    }

    var params =
        {
            token: oAuthToken.replace("access_token=", "").replace("&scope=repo&token_type=bearer", "")
        };
    makeCall(callback, './gitCaptain/logOff', 'POST', params)
}

function getUserAuthCode() {
    window.open('https://github.com/login/oauth/authorize?client_id=' + clientID + '&scope=repo', '_self');
}

function getAuthCode(url) {
    var error = url.match(/[&?]error=([^&]+)/);
    if (error) {
        throw 'Error getting authorization code: ' + error[1];
    }
    return url.match(/[&?]code=([\w\/\-]+)/)[1];
}

function getAccessToken() {

    makeCall(
        oAuthResponse,
        gitPortEndPoint + "/gitCaptain/getToken?code=" + authCode,
        "POST",
        null
    );
}

function oAuthResponse(data) {
    $('#loading').hide();
    if (data != null && data.body.indexOf("error=") === -1) {
        oAuthToken = data.body;
        $('#authDiv').show();
        getUserName();
    }
    else {
        $('#l').show();
    }
}

/*** end login/logout functions ***/


function setTimeoutTimer() {
    if (typeof timeOutObj !== "undefined") {
        clearTimeout(timeOutObj);
    }

    timeOutObj = setTimeout(function () {
        logOff(true);
    }, timeOutInMinutes * 60 * 1000);
}

function makeCall(callback, url, method, params, token) {
    var _url = url;
    var _method = method;
    var headers = {};
    
    // Add authorization header if token is provided
    if (token) {
        headers['Authorization'] = 'token ' + token;
    }

    switch (method) {
        case "GET":
            $.ajax({
                url: _url,
                type: _method,
                headers: headers,
                success: callback,
                error: callback,
                async: true
            });
            break;

        case "POST":
            $.ajax({
                url: _url,
                type: _method,
                headers: headers,
                success: callback,
                error: callback,
                data: params
            });
            break;

        case "DELETE":
            $.ajax({
                url: _url,
                type: _method,
                headers: headers,
                success: callback,
                error: callback,
                data: params
            });
            break;

        default:
            return "Not Ready Yet";
    }
}