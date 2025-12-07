function prepareForBranchCreation() {
    var selectedRepos = [];
    repoCount = 0;
    var newBranchValue = $('#newBranch')[0].value;
    var refBranchValue = $('#refBranch')[0].value;

    $.each($("input[name='repoList']:checked"), function () {
        selectedRepos.push($(this).val());
    });

    showSpinner();
    if (newBranchValue === '' || refBranchValue === '') {
        alert("Both branch From and New branch must be populated");
        hideSpinner();
    }
    else {
        createBranches('', newBranchValue.trim().replace(/\s+/g, '-'), refBranchValue.trim().replace(/\s+/g, '-'),selectedRepos);
    }
}
function createBranches(repoName, branchToCreate, fromBranch, selectedRepos) {

    if (repoName === '') {
        repoName = selectedRepos[0];
    }

    function callback(data) {
        logNumber += 1;
        if (data.statusCode === 422) {
            addRow(branchToCreate + " already existed in " + repoName, repoName, branchToCreate, "FAILURE", logNumber, orgName);
        }
        else if (data.statusCode === 201) {
            addRow(branchToCreate + " created in " + repoName, repoName, branchToCreate, "SUCCESS", logNumber, orgName);
        }
        else if (data.statusCode === 404) {
            addRow("The " + fromBranch + " branch you requested to branch off from does not exist in " + repoName + " repository.", repoName, branchToCreate, "FAILURE", logNumber, orgName);
        }
        else {
            addRow("Error creating " + branchToCreate + " in " + repoName, repoName, branchToCreate, "FAILURE", logNumber, orgName);
        }

        repoCount += 1;

        if (repoCount < selectedRepos.length) {
            createBranches(selectedRepos[repoCount], branchToCreate, fromBranch, selectedRepos);
        }
        else {
            alert("Branch creation complete");
            selectedRepos = [];
            applyBottomBorder();
            hideSpinner();
        }
    }

    var params =
        {
            branchRef: fromBranch,
            newBranch: branchToCreate,
            repo: repoName,
            token: oAuthToken.replace("access_token=", "").replace("&scope=repo&token_type=bearer", "")
        };

    makeCall(callback, './gitCaptain/createBranches', 'POST', params)
}

function prepareForPRSearch() {
    console.log('prepareForPRSearch called, arrayOfRepos:', arrayOfRepos);
    // Check if repositories are loaded
    if (!arrayOfRepos || arrayOfRepos.length === 0) {
        alert("No repositories loaded. Please wait for repositories to load and try again.");
        return;
    }
    
    var searchPRinputVal = $("#searchPRinput").val();
    console.log('PR search input value:', searchPRinputVal);
    if (searchPRinputVal === '') {
        alert("Search branch field must be populated");
        hideSpinner();
    }
    else {
        showSpinner();
        repoCountForPRSearch = 0;
        console.log('Starting PR search for branch:', searchPRinputVal, 'in repos:', arrayOfRepos.length);
        searchPullRequestsInAllRepos(arrayOfRepos[0].name.toString(), searchPRinputVal.trim(), 'open',arrayOfRepos);
    }
}
function searchPullRequestsInAllRepos(repoNameToSearch, branchToSearchFor, stateOfPullRequest, arrayOfRepos) {

    function callback(data) {
        console.log('PR search response for', repoNameToSearch, ':', data);
        if (data.statusCode === 200) {
            var pullRequests = JSON.parse(data.body);
            console.log('Found', pullRequests.length, 'pull requests for', branchToSearchFor, 'in', repoNameToSearch);

            if (pullRequests.length > 0) {
                for (var i = 0; i < pullRequests.length; i++) {
                    logNumber += 1;
                    // noinspection JSUnresolvedVariable
                    addRowForPR(pullRequests[i].html_url, pullRequests[i].user.login, repoNameToSearch, branchToSearchFor, logNumber, orgName)
                }
            } else {
                logNumber += 1;
                addRow("No pull requests found for " + branchToSearchFor + " in " + repoNameToSearch, repoNameToSearch, branchToSearchFor, "NOT FOUND", logNumber, orgName);
            }
        } else {
            console.log('PR search error for', repoNameToSearch, 'status:', data.statusCode);
            logNumber += 1;
            addRow("Error searching for pull requests in " + repoNameToSearch, repoNameToSearch, branchToSearchFor, "ERROR", logNumber, orgName);
        }

        repoCountForPRSearch += 1;

        if (repoCountForPRSearch < arrayOfRepos.length) {
            searchPullRequestsInAllRepos(arrayOfRepos[repoCountForPRSearch].name, branchToSearchFor, stateOfPullRequest,arrayOfRepos);
        }
        else {
            alert("Done searching for pull requests.");
            applyBottomBorder();
            hideSpinner();
        }

    }

    var params =
        {
            state: stateOfPullRequest,
            prBaseBranch: branchToSearchFor,
            repo: repoNameToSearch,
            token: oAuthToken.replace("access_token=", "").replace("&scope=repo&token_type=bearer", "")
        };

    makeCall(callback, './gitCaptain/searchForPR', 'POST', params)

}

function prepareForBranchSearch() {
    var searchInputVal = $("#searchInput").val();
    if (searchInputVal === '') {
        alert("Search branch field must be populated");
        hideSpinner();
    }
    else {
        showSpinner();
        repoCountForSearch = 0;
        searchBranchesInAllRepos(arrayOfRepos[0].name.toString(), searchInputVal.trim(),arrayOfRepos);
    }
}
function searchBranchesInAllRepos(repoNameToSearch, branchToSearchFor, arrayOfRepos) {
    function callback(data) {
        logNumber += 1;
        if (data.statusCode === 404) {
            addRow("Could not find " + branchToSearchFor + " in " + repoNameToSearch, repoNameToSearch, branchToSearchFor, "NOT FOUND", logNumber, orgName);
        }
        else if (data.statusCode === 200) {
            addRow(branchToSearchFor + " was found in " + repoNameToSearch, repoNameToSearch, branchToSearchFor, "FOUND", logNumber, orgName);
        }

        repoCountForSearch += 1;

        if (repoCountForSearch < arrayOfRepos.length) {
            searchBranchesInAllRepos(arrayOfRepos[repoCountForSearch].name, branchToSearchFor, arrayOfRepos);
        }
        else {
            alert("Done searching for branches.");
            applyBottomBorder();
            hideSpinner();
        }
    }

    var params =
        {
            searchForBranch: branchToSearchFor,
            repo: repoNameToSearch,
            token: oAuthToken.replace("access_token=", "").replace("&scope=repo&token_type=bearer", "")
        };

    makeCall(callback, './gitCaptain/searchForBranch', 'POST', params)
}

function prepareForBranchDeletion(arrayOfRepos) {

    var deleteInputValue = $("#deleteInput").val();

    if (deleteInputValue === '') {
        alert("Delete branch field must be populated");
        hideSpinner();
    }
    else {
        var r = confirm("This is a destructive operation, and cannot be undone. Press OK to continue, or CANCEL to cancel.");
        if (r) {
            showSpinner();
            repoCountForDelete = 0;
            deleteBranchFromAllRepos(arrayOfRepos[0].name.toString(), deleteInputValue.trim(),arrayOfRepos);
        }
    }
}
function deleteBranchFromAllRepos(repoNameForDelete, branchToDelete,arrayOfRepos) {
    if (branchToDelete.toLowerCase() === 'master') {
        alert("We do not support deleting master from this site!!");
        hideSpinner();
    }
    else {

        function callback(data) {
            logNumber += 1;
            if (data.statusCode === 422) {
                addRow("Could not find " + branchToDelete + " in " + repoNameForDelete, repoNameForDelete, branchToDelete, "FAILURE", logNumber, orgName);
            }
            else if (data.statusCode === 204) {
                addRow(branchToDelete + " deleted from " + repoNameForDelete, repoNameForDelete, branchToDelete, "SUCCESS", logNumber, orgName);
            }
            repoCountForDelete += 1;

            if (repoCountForDelete < arrayOfRepos.length) {
                deleteBranchFromAllRepos(arrayOfRepos[repoCountForDelete].name, branchToDelete,arrayOfRepos);
            }
            else {
                alert("Done deleting branches");
                applyBottomBorder();
                hideSpinner();
            }
        }

        var params =
            {
                deleteBranch: branchToDelete,
                repo: repoNameForDelete,
                token: oAuthToken.replace("access_token=", "").replace("&scope=repo&token_type=bearer", "")
            };

        makeCall(callback, './gitCaptain/deleteBranches', 'DELETE', params)
    }

}