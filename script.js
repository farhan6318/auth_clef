$(window).load(
    function () {
        // CODE HIGHLY INSPIRED FROM ELCENTRA OAUTH2 PLUGIN: https://moodle.org/plugins/view/auth_elcentra

        if ($("#auth_custom_location").length > 0) {
            $("#auth_custom_location").append(buttonsCodeClef);
        } else {
            var formObj = $("input[name='username']").closest("form");
            if (formObj.length > 0) {
                $(formObj).each(function (i, formItem) {
                    var username = $(formItem).find("input[name='username']").val();
                    var password = $(formItem).find("input[name='password']").val();
                    if(username !== "guest" || password !== "guest") {
                        $(formItem).append(buttonsCodeClef);
                    }
                });
            }
        }


    }
)

