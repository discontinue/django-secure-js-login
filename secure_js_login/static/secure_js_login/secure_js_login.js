/*
    PyLucid secure_js_login.js
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~
    
    A secure JavaScript SHA-1 AJAX Login.
    
    :copyleft: 2007-2015 by the PyLucid team, see AUTHORS for more details.
    :license: GNU GPL v3 or above, see LICENSE for more details
*/

// helper function for console logging
// set debug to true to enable debug logging
function log() {
    if (typeof DEBUG === 'undefined') {
        window.console.log("DEBUG variable is undefined -> no debugging.");
        DEBUG=false;
    }
    if (DEBUG && window.console && window.console.log) {
        try {
            window.console.log(Array.prototype.join.call(arguments,''));
        } catch (e) {
            log("Error:" + e);
        }

    }
}
log("JS logging initialized");

try {
    jQuery(document);
    log("jQuery loaded, ok.");
} catch (e) {
    alert("Error, jQuery JS not loaded!\n Original error was:" + e);
}


function replace_complete_page(html) {
    // replace the complete page
    if (html.indexOf("</body>") == -1) {
        document.open("text/plain");
    } else {
        document.open("text/html");
    }
    document.write(html);
    document.close();
}

function ajax_error_handler(XMLHttpRequest, textStatus, errorThrown) {
    /*************************************************************************
	ajax error "handler".
	replace the complete page with the error text (django html traceback page)
	*************************************************************************/
    log("ajax get response error!");
    log("textStatus:" + textStatus);
    log("errorThrown:" + errorThrown);
    log(XMLHttpRequest);
    var response_text = XMLHttpRequest.responseText;
    //log("response_text: '" + response_text + "'");
    if (!response_text) {
        response_text = "Ajax response error without any response text.\n";
		response_text += "textStatus:" + textStatus + "\n";
		response_text += "errorThrown:" + errorThrown + "\n";
		replace_complete_page(response_text)
		return false;
    }
    replace_complete_page(response_text);
    load_normal_link = true;
    return false;
}


function _page_msg(msg){
    $("#js_page_msg").html(msg).slideDown().css("display", "block");
}
function page_msg_error(msg) {
    $("#js_page_msg").removeClass("page_msg_info page_msg_success").addClass("page_msg_error");
    _page_msg(msg);
}
function page_msg_success(msg) {
    $("#js_page_msg").removeClass("page_msg_info page_msg_success").addClass("page_msg_success");
    _page_msg(msg);    
}
function page_msg_info(msg) {
    $("#js_page_msg").removeClass("page_msg_success page_msg_error").addClass("page_msg_info");
    _page_msg(msg);    
}


function low_level_error(msg) {
    log(msg);
    $("#page_content").html("<"+"h2>" + msg + "<"+"/h2>");
    alert(msg);
    return false;
}

function assert_global_variable_exists(name) {
    if (name in window) {
        log("global variable " + name + " exists.")
        return eval(name)
    } else {
        throw "global variable '"+name+"' doesn't exists!";
    }
}

function assert_is_number(name) {
    value = assert_global_variable_exists(name);
    if(value=="") {
        throw "Variable '"+name+"' from server is a empty string!";
    }
    if(isNaN(value)) {
        throw "Variable '"+name+"' from server is not a number! It's: ["+value+"]";
    }
    log("assert_is_number for '"+name+"', ok (value="+value+")");
}

function assert_length(value, must_length, name) {
    if (value.length != must_length) {
        throw "Error: '"+name+"' has wrong length:" + value.length + "!=" + must_length + " (value:'"+value+"')";
    } else {
        log("assert length of '"+name+"', ok (length == "+value.length+")");
    }
}

function assert_variable_length(name, must_length) {
    value = assert_global_variable_exists(name);
    assert_length(value, must_length, name);
}

function assert_min_length(value, min_length, name) {
    if (value.length < min_length) {
        var msg="Error: '"+name+"' is too short. It must be at least "+min_length+" characters long.";
        log(msg);
        throw msg;
    } else {
        log("assert min length of '"+name+"', ok (length == "+value.length+" < "+min_length+")");
    }
}


function assert_only_ascii(data) {
    // Check if the given string contains only ASCII characters
    for (var i = 1; i <= data.length; i++) {
        var char_code=data.charCodeAt(i)
        if (char_code > 127) {
            throw "Error: non ASCII caracter '"+data.substr(i,1)+"' (unicode no. "+char_code+") in '"+data+"'!";
        }
    }
}

//-----------------------------------------------------------------------------

function assert_csrf_cookie() {
    // Check if Cross Site Request Forgery protection cookie exists
    if ((typeof document.cookie === 'undefined') || (document.cookie.indexOf("csrftoken") == -1)) {
        try {
            log("Cookies: " + document.cookie);
        } catch (e) {
            log("Error:" + e);
        }
        throw "Error: Cookies not set. Please enable cookies in your browser!";
    }
}
function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie != '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = jQuery.trim(cookies[i]);
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) == (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}
function csrfSafeMethod(method) {
    // these HTTP methods do not require CSRF protection
    return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
}


function init_ajax_csrf() {
    assert_csrf_cookie()

    var csrftoken = getCookie(CSRF_COOKIE_NAME);

    $.ajaxSetup({
        beforeSend: function(xhr, settings) {
            if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
                xhr.setRequestHeader("X-CSRFToken", csrftoken);
            }
        }
    });
    log("Ajax CSRF cookie handling initilized with: " + csrftoken);
}

//-----------------------------------------------------------------------------

function generate_nonce(start_value) {
    // Generate new 'cnonce' a client side random value
    var cnonce = start_value;
    cnonce += new Date().getTime();
    cnonce += Math.random();
    cnonce += $(window).height();
    cnonce += $(window).width();
    //cnonce = "Always the same, test.";
    log("generated cnonce from:" + cnonce);
    cnonce = sha_hexdigest(cnonce);
    log("SHA cnonce....: '" + cnonce + "'");
    cnonce = cnonce.substr(0, NONCE_LENGTH);
    log("cnonce cut to.: '" + cnonce + "'");
    return cnonce
}

function sha_hexdigest(txt) {
    /*
        build the SHA hexdigest from the given string. Return false is anything is wrong.
    */
    log("sha_hexdigest('" + txt + "'):");
    var SHA_hexdigest = hex_sha1(txt); // from: sha.js
    assert_length(SHA_hexdigest, 40, "SHA_hexdigest");
    log(SHA_hexdigest);
    return SHA_hexdigest;
}

function pbkdf2(txt, salt, iterations, callback, bytes=PBKDF2_BYTE_LENGTH) {
    log("pbkdf2 calc with iterations: " + iterations + " - bytes: " + bytes)
    var mypbkdf2 = new PBKDF2(password=txt, salt=salt, iterations=iterations, bytes=bytes);
    mypbkdf2.deriveKey(
        function(percent_done) {
            var msg="Computed " + Math.floor(percent_done) + "%";
//            log(msg);
            $(ID_PASSWORD).val(msg);
        },
        function(key) {
            var msg="The derived " + (bytes*8) + "-bit key is: " + key;
            log(msg);
            $(ID_PASSWORD).val(key);
            callback(key);
        }
    );
}

function test_pbkdf2_js() {
    log("Check pbkdf2.js...");

    if (typeof PBKDF2 === 'undefined') {
        throw "Error:\npbkdf2.js not loaded.\n(PBKDF2 not defined)";
    }

    var old_value = $(ID_PASSWORD).val();
    pbkdf2(
        txt=test_string,
        salt=test_string,
        iterations=5,
        callback=function(key) {
            var should_be = '4460365dc7df037dbdd851f1ffed7130';
            if (key == should_be) {
                log("Check PBKDF2 function is ok.");
                $(ID_PASSWORD).val(old_value);
            } else {
                msg = "ERROR: pbkdf2.js test failed!\n'" + key + "' != '" + should_be + "'"
                alert(msg);
                throw msg;
            }
        },
        bytes=16
    );
}


function calculate_hashes(password, salt, challenge, callback) {
    log("calculate_hashes with salt '"+salt+"' (length:"+salt.length+") and challenge '"+challenge+"' (length:"+challenge.length+")");
    
    assert_length(salt, SALT_LENGTH, "salt");
    assert_length(challenge, CHALLENGE_LENGTH, "challenge");

    log('pbkdf2_temp_hash = pbkdf2("Plain Password", init_pass_salt):');

    var old_value = $(ID_PASSWORD).val();
    pbkdf2(password, salt, ITERATIONS1, function(pbkdf2_temp_hash) {
        log("pbkdf2_temp_hash = " + pbkdf2_temp_hash);

        // split pbkdf2_temp_hash
        first_pbkdf2_part = pbkdf2_temp_hash.substr(0, PBKDF2_BYTE_LENGTH);
        second_pbkdf2_part = pbkdf2_temp_hash.substr(PBKDF2_BYTE_LENGTH, PBKDF2_BYTE_LENGTH);
        log("split: |"+first_pbkdf2_part+"|"+second_pbkdf2_part+"|");
        log("first_pbkdf2_part = " + first_pbkdf2_part);
        log("second_pbkdf2_part = " + second_pbkdf2_part);

        var cnonce = generate_nonce("django secure JS login");
        assert_length(cnonce, NONCE_LENGTH, "cnonce");

        log("second_pbkdf2_salt = cnonce + server_challenge");
        second_pbkdf2_salt = cnonce + challenge;
        log("second_pbkdf2_salt = " + second_pbkdf2_salt);

        log("pbkdf2_hash = pbkdf2(first_pbkdf2_part, salt=cnonce + server_challenge)");
        pbkdf2(first_pbkdf2_part, second_pbkdf2_salt, ITERATIONS2, function(pbkdf2_hash) {
            log("pbkdf2_hash = " + pbkdf2_hash);
            log("result = pbkdf2_hash + $ + second_pbkdf2_part + $ + cnonce")
            var result = pbkdf2_hash + "$" + second_pbkdf2_part + "$" + cnonce;
            log("result = " + result);
            $(ID_PASSWORD).val(result);
            return callback();
        });
    });
}


//-----------------------------------------------------------------------------

var digits="0123456789";
var ascii_lowercase = "abcdefghijklmnopqrstuvwxyz".toLowerCase();
var ascii_uppercase = ascii_lowercase.toUpperCase();
var test_string = " " + digits + ascii_lowercase + ascii_uppercase;


function test_sha_js() {
    log("Check sha.js...");
    
    if (typeof hex_sha1 === 'undefined') {
        throw "Error:\nsha.js not loaded.\n(hex_sha1 not defined)";
    }

    if (typeof sha_hexdigest === 'undefined') {
        throw "Error:\nWrong secure_js_login.js loaded! Please update your static files\n(sha_hexdigest not defined)";
    }

    var test_sha = sha_hexdigest(test_string);
    var should_be = "5b415e2e5421a30b798c9b46638fcd7b58ff4d53".toLowerCase();
    if (test_sha != should_be) {
        throw "sha.js test failed!\n'" + test_sha + "' != '" + should_be + "'";
    }
    log("Check the sha1 functions is ok.");
}

var precheck_secure=false;
function precheck_secure_login() {
    init_ajax_csrf() // Cross Site Request Forgery protection

    assert_is_number("CHALLENGE_LENGTH");
    assert_is_number("NONCE_LENGTH");
    assert_is_number("SALT_LENGTH");
    assert_is_number("PBKDF2_BYTE_LENGTH");
    assert_is_number("ITERATIONS1");
    assert_is_number("ITERATIONS2");

    assert_variable_length("challenge", CHALLENGE_LENGTH);

    test_sha_js(); // Check the sha1 functions from external js files
    test_pbkdf2_js();

    precheck_secure=true;
}


//-----------------------------------------------------------------------------
function sleep(milliseconds) {
  var start = new Date().getTime();
  for (var i = 0; i < 1e7; i++) {
    if ((new Date().getTime() - start) > milliseconds){
      break;
    }
  }
}

function init_secure_login() {
    /*
        Secure-JS-Login
        init from /secure_js_login/sha_form.html
    */
    $("#content-main").append('<p id="init_message">init...</p>');

    log("secure_js_login.js - init_secure_login()");
    
    try {
        precheck_secure_login()
    } catch (e) {
        low_level_error(e);
        return false;
    }

    $(ID_USERNAME).change(function() {
        // if the username change, we must get a new salt from server.
        $(ID_PASSWORD).focus();
        log("username changed, delete old salt.");
        salt="";
        return false;
    });

//    $(ID_USERNAME).val("test"); // XXX: for testing only!!!
//    setTimeout(function() { $(ID_PASSWORD).val("12345678"); }, 2); // XXX: for testing only!!!

    var submit_by="user";
    var salt=""; // will be set via ajax
    $(ID_FORM).submit(function() {
        log("check login form (submit_by='"+submit_by+"')");
        try {
            if (submit_by=="callback") {
                log("Send form...");
                return true;
            } else if (submit_by=="user") {
                var username = $(ID_USERNAME).val();
                log("username:" + username);

                if (username.length<2) {
                    log("username to short, current len:" + username.length);
                    page_msg_error(gettext("Username is too short."));
                    $(ID_USERNAME).focus();
                    return false;
                }

                var password = $(ID_PASSWORD).val();
                log("password:" + password);

                try {
                    assert_min_length(password, 8, "password");
                } catch (e) {
                    log(e);
                    var msg=gettext("Password is too short. It must be at least eight characters long.");
                    alert(msg);
    //                page_msg_error(msg);
                    $(ID_PASSWORD).focus();
                    return false;
                }

                try {
                    assert_only_ascii(password)
                } catch (e) {
                    log(e);
                    var msg=gettext("Only ASCII letters in password allowed!");
                    alert(msg);
    //                page_msg_error(msg);
                    $(ID_PASSWORD).focus();
                    return false;
                }

                $(ID_PASSWORD).val("wait...");
                $(ID_PASSWORD).attr("type", "text");

                if (salt=="") {
                    $(ID_PASSWORD).val(gettext("Get salt from server..."));

                    var post_data = {
                        "username": username
                    };
                    log("get user salt from " + get_salt_url + " - send POST:" + $.param(post_data));
                    response = $.ajax({
                        async: false,
                        type: "POST",
                        url: get_salt_url,
                        data: post_data,
                        dataType: "text",
                        success: function(data, textStatus, XMLHttpRequest){
                            log("get salt value via ajax: " + textStatus);
                        },
                        error: ajax_error_handler
                    });
                    salt = response.responseText;
                    log("salt value from server:" + salt);
                } else {
                    log("use existing salt:" + salt);
                }
                try {
                    assert_length(salt, SALT_LENGTH, "salt");
                } catch (e) {
                    log(e);
                    alert("Internal error: Wrong salt length:" + salt.length + "!=" + SALT_LENGTH);
                    return false;
                }

                $(ID_PASSWORD).val(gettext("Calculate the hashes..."));
                calculate_hashes(password, salt, challenge, callback=function(){
                    submit_by="callback";
                    $("form input:submit").click();
                });
                return false
            } else {
                throw "submit_by value: '"+submit_by+"' unknown?!?"
            }
        } catch (e) {
            log("Error:" + e);
            alert("internal javascript error:" + e);
        }
        return false;
    });

    $("#init_message").slideUp();
    $("form").slideDown();
    $(ID_USERNAME).focus();
}


//-----------------------------------------------------------------------------

function change_password_submit() {
    /*
    calculate the hashes from the passwords and insert only them into
    the form and remove the plaintext passwords.
    */
    log("check change password form.");
    
    var old_password = $("#id_old_password").val();
    log("old_password:" + old_password);

    var new_password1 = $("#id_new_password1").val();
    log("new_password1:" + new_password1);

    var new_password2 = $("#id_new_password2").val();
    log("new_password2:" + new_password2);

    try {
        assert_min_length(old_password, 8, "old password");
    } catch (e) {
        page_msg_error(e);
        $("#id_old_password").focus();
        return false;
    }
    
    try {
        assert_min_length(new_password1, 8, "new password");
    } catch (e) {
        page_msg_error(e);
        $("#id_new_password1").focus();
        return false;
    }
    
    try {
        assert_only_ascii(old_password)
    } catch (e) {
        log(e);
        page_msg_error(gettext("Error: Old password contains non ASCII letters!"));
        $("#id_old_password").focus();
        return false;
    }
    
    try {
        assert_only_ascii(new_password1)
    } catch (e) {
        log(e);
        page_msg_error(gettext("Error: New password contains non ASCII letters!"));
        $("#id_new_password2").val("");
        $("#id_new_password1").focus();
        return false;
    }
    
    if (new_password1 != new_password2) {
        msg = gettext("The two password fields didn't match.")
        log(msg + " -> " + new_password1 + " != " + new_password2);
        page_msg_error(msg);
        $("#id_new_password2").focus();
        return false;
    }
    
    if (new_password1 == old_password) {
        var result=confirm("The new password is the same as the old password.");
        if (result != true) {
            return false
        }
    }

    // display SHA values
    $("#password_block").slideUp(1).delay(500);
    $("#sha_values_block").css("display", "block").slideDown();

    try {
        var results=calculate_hashes(old_password, sha_login_salt, challenge);
    } catch (e) {
        alert(e);
        return false;
    }
    var sha_a=results.sha_a;
    var sha_b=results.sha_b;
    var cnonce=results.cnonce;
    log("sha_a:"+sha_a);
    log("sha_b:"+sha_b);
    log("cnonce:"+cnonce);
   
    // old password "JS-SHA1" values for pre-verification
    $("#id_sha_a").val(sha_a);
    $("#id_sha_b").val(sha_b);
    $("#id_cnonce").val(cnonce);
            
    $("#id_old_password").val(""); // 'delete' plaintext password
    $("#id_old_password").remove();
    
    var salted_hash=calculate_salted_sha1(new_password1);
    var salt=salted_hash.salt;
    var sha1hash=salted_hash.sha1hash;
    log("new salted hash:");
    log("salt: "+salt+" (length:"+salt.length+")");
    log("sha1hash: "+sha1hash+" (length:"+sha1hash.length+")");
   
    // new password as salted SHA1 hash:
    $("#id_salt").val(salt);
    $("#id_sha1hash").val(sha1hash);

    $("#id_new_password1").val(""); // 'delete' plaintext password
    $("#id_new_password1").remove();
    $("#id_new_password2").val(""); // 'delete' plaintext password
    $("#id_new_password2").remove();

}

function init_JS_password_change() {
    /*
        change user password
        init from auth/JS_password_change.html
    */
    log("secure_js_login.js - init_JS_password_change()");
    
    try {
        precheck_secure_login();
        
        // unlike normal login, we have the salt directly, set in template
        assert_salt_length(sha_login_salt)
    } catch (e) {
        log(e);
        alert("Error:" + e);
        return false;
    }
    
    $("#id_old_password").focus();
    
    $("input").change(function() {
        // hide old JS messages, if a input field changed
        $("#js_page_msg").slideUp(50);
    });
    
    $("#change_password_form").submit(function() {
        $("#js_page_msg").slideUp(50); // hide old JS messages
        try {
            return change_password_submit();
        } catch (e) {
            log(e);
            alert("Error:" + e);
            return false;
        }
        //return confirm("Send?");
    });
    $("#load_info").slideUp();
}
