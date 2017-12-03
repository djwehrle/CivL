"use strict";

$(document).ready(function () {

    $("#allLaws").DataTable();

    $("#allLaws tbody tr").click(function () {
        location.href = "/Laws/" + $(this).data("law-id");
    });

});