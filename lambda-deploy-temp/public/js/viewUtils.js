function applyBottomBorder() {
    $('#logTable tr:last').css('border-bottom', '4px solid gray');
}

function buildTypeChange() { //TODO: remove sice this is no longer necessary.
    $('li').show();
}

function clearLog() {
    $("#logTableDiv").html("<table id=\"logTable\" style=\"font-size:10pt;\" ><tr><th>Number</th><th>Action</th><th>Repo</th><th>Branch</th><th>Result</th></tr></table>");
    logNumber = 0;
}

function hideSpinner() {
    modalSpinner.hide();
}

function showSpinner() {
    modalSpinner.show();
}

function toggleViews() {
    if ($('input#create')[0].checked) //Create selected
    {
        $('#branchDeleter').hide();
        $('#branchFinder').hide();
        $('#pullRequestFinder').hide();
        $('#branchMaker').show();
    }
    else if ($('input#delete')[0].checked)  //Delete selected
    {
        $('#branchMaker').hide();
        $('#branchFinder').hide();
        $('#pullRequestFinder').hide();
        $('#branchDeleter').show();
    }
    else if ($('input#findPullRequests')[0].checked)  //Delete selected
    {
        $('#branchDeleter').hide();
        $('#branchMaker').hide();
        $('#branchFinder').hide();
        $('#pullRequestFinder').show();
    }
    else {
        $('#branchMaker').hide();
        $('#branchDeleter').hide();
        $('#pullRequestFinder').hide();
        $('#branchFinder').show();
    }
}

function addRow(actionMsg, repoMsg, branchMsg, resultMsg, logNumber, orgName) {

    var markup;
    if (resultMsg === "FAILURE" || resultMsg === "NOT FOUND") {
        markup = "<tr><td>" + logNumber + "</td><td>" + actionMsg + "</td><td>" + "<a style=\"color: #616161\" href=" + 'https://github.com/' + orgName + '/' + repoMsg + " target=\"_blank\">" + repoMsg + "</td><td>" + branchMsg + "</td><td style=\"background: #960d0d;\">" + resultMsg + "</td></tr>";
    }
    else if (resultMsg === "Pull Request Found") {
        markup = "<tr><td>" + logNumber + "</td><td>" + actionMsg + "</td><td>" + "<a style=\"color: #616161\" href=" + 'https://github.com/' + orgName + '/' + repoMsg + " target=\"_blank\">" + repoMsg + "</td><td>" + branchMsg + "</td><td>" + resultMsg + "</td></tr>";
    }
    else {
        markup = "<tr><td>" + logNumber + "</td><td>" + actionMsg + "</td><td>" + "<a style=\"color: #616161\" href=" + 'https://github.com/' + orgName + '/' + repoMsg + " target=\"_blank\">" + repoMsg + "</td><td>" + branchMsg + "</td><td>" + resultMsg + "</td></tr>";
    }
    $("#logTable").append(markup);
}

function addRowForPR(pullRequestURL, creator, repoNameToSearch, branchToSearchFor, logNumber, orgName) {
    var markup = "<tr><td>" + logNumber + "</td><td>" + "<a href=\"" + pullRequestURL + "\" class=\"link-gray-dark v-align-middle no-underline h4 js-navigation-open\" target=\"_blank\">" + pullRequestURL + " </a>" + " created by " + creator + "</td><td>" + "<a style=\"color: #616161\" href=" + 'https://github.com/' + orgName + '/' + repoNameToSearch + " target=\"_blank\">" + repoNameToSearch + "</a></td><td>" + branchToSearchFor + "</td><td>Pull Request Found</td></tr>";
    $("#logTable").append(markup);
}

function populateList(listItems) {

    var assetList = $('#repoUl');

    $.each(listItems, function (i) {
        var liHtml = "<li><input type=\"checkbox\" id=\"" + listItems[i].name + "\" name=\"repoList\" value=\"" + listItems[i].name + "\" /><label for=\"" + listItems[i].name + "\"style=\"vertical-align: super;\">" + listItems[i].full_name + "</label></li>";
        assetList.append(liHtml);
    });

}
