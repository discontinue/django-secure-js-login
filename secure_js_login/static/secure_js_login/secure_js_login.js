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


/**********************************************************
    Some low-level helper functions
**********************************************************/
function string2Uint8Array(text) {
    // FIXME: How can this be easier?!?
    var buffer = new Uint8Array(text.length);
    for (var i = 0; i < text.length; i++) {
        buffer[i] = text.charCodeAt(i);
    }
    return buffer
}
function Uint8Array2string(buffer) {
    // FIXME: How can this be easier?!?
    var text = ""
    for (var i=0; i<buffer.byteLength; i++) {
        text += String.fromCharCode(buffer[i])
    }
    return text
}
function hex(buffer) {
    // from example here:
    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest
    var hexCodes = [];
    var view = new DataView(buffer);
    for (var i = 0; i < view.byteLength; i += 4) {
        // Using getUint32 reduces the number of iterations needed (we process 4 bytes each time)
        var value = view.getUint32(i)
        // toString(16) will give the hex representation of the number without padding
        var stringValue = value.toString(16)
        // We use concatenation and slice for padding
        var padding = '00000000'
        var paddedValue = (padding + stringValue).slice(-padding.length)
        hexCodes.push(paddedValue);
    }
    return hexCodes.join(""); // Join all the hex strings into one
}


//-----------------------------------------------------------------------------


try {
    jQuery(document);
    log("jQuery loaded, ok.");
} catch (e) {
    alert("Error, jQuery JS not loaded!\n Original error was:" + e);
}


function replace_complete_page(html) {
    // replace the complete page
    if (html.indexOf("</body>") == -1) {
        html = "<pre>\n"+html+"\n</pre>";
    }
    $("body").replaceWith(html);
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
    return sha512_hexdigest(cnonce).then(function(cnonce){
        log("SHA cnonce....: '" + cnonce + "'");
        cnonce = cnonce.substr(0, NONCE_LENGTH);
        log("cnonce cut to.: '" + cnonce + "'");
        return cnonce
    });
}

function sha_hexdigest(txt, prefix) {
    /*
        build the SHA hexdigest from the given string. Return false is anything is wrong.
    */
    log("SHA-"+prefix+" from: '" + txt + "'");

    // TODO: add work-a-round if TextEncoder not supported
    // IE / Safari, see:
    // https://developer.mozilla.org/en-US/docs/Web/API/TextEncoder
    var buffer = new TextEncoder("utf-8").encode(txt);

    return window.crypto.subtle.digest("SHA-"+prefix, buffer).then(function (hash) {
        return hex(hash);
    });
}
function sha1_hexdigest(txt) {
    return sha_hexdigest(txt, 1);
}
function sha512_hexdigest(txt) {
    return sha_hexdigest(txt, 512);
}


function pbkdf2(txt, salt, iterations, bytes) {
    if (typeof(bytes)==='undefined') bytes = PBKDF2_BYTE_LENGTH;

    log("pbkdf2 calc with iterations: " + iterations + " - bytes: " + bytes)

    // TODO: add work-a-round if TextEncoder not supported
    // IE / Safari, see:
    // https://developer.mozilla.org/en-US/docs/Web/API/TextEncoder
    txt = new TextEncoder("utf-8").encode(txt);

    return window.crypto.subtle.importKey(
        "raw", txt, {name: "PBKDF2"},
        false, //whether the key is extractable (i.e. can be used in exportKey)
        ["deriveBits"] // ["deriveKey", "deriveBits"] //can be any combination of "deriveKey" and "deriveBits"
    ).then(function(key){
        salt = new TextEncoder("utf-8").encode(salt);
        return window.crypto.subtle.deriveBits(
            {
                "name": "PBKDF2",
                salt: salt,
                iterations: iterations,
                hash: {name: "SHA-1"},
            },
            key, bytes*8
        ).then(function(hash){ // get a ArrayBuffer back
            var hex_hash=hex(hash);
            log("The derived " + (bytes*8) + "-bit key is: " + hex_hash);
            return hex_hash;
        })
    })
}

function test_pbkdf2_js() {
    log("Check pbkdf2()");
    return pbkdf2(
        txt=test_string,
        salt=test_string,
        iterations=5,
        bytes=16
    ).then(function(hex_hash){
        var should_be = '4460365dc7df037dbdd851f1ffed7130';
        if (hex_hash == should_be) {
            log("Check PBKDF2 passed.");
        } else {
            msg = "ERROR: PBKDF2 test failed!\n'" + hex_hash + "' != '" + should_be + "'"
            alert(msg);
            throw msg;
        }
    })
}


function calculate_hashes(password, salt, challenge) {
    log("calculate_hashes with salt '"+salt+"' (length:"+salt.length+") and challenge '"+challenge+"' (length:"+challenge.length+")");
    
    assert_length(salt, SALT_LENGTH, "salt");
    assert_length(challenge, CHALLENGE_LENGTH, "challenge");

    log('pbkdf2_temp_hash = pbkdf2("Plain Password", init_pass_salt):');

    var old_value = $(ID_PASSWORD).val();
    return pbkdf2(password, salt, ITERATIONS1).then(function(pbkdf2_temp_hash){
        log("pbkdf2_temp_hash = " + pbkdf2_temp_hash);

        // split pbkdf2_temp_hash
        first_pbkdf2_part = pbkdf2_temp_hash.substr(0, PBKDF2_BYTE_LENGTH);
        second_pbkdf2_part = pbkdf2_temp_hash.substr(PBKDF2_BYTE_LENGTH, PBKDF2_BYTE_LENGTH);
        log("split: |"+first_pbkdf2_part+"|"+second_pbkdf2_part+"|");
        log("first_pbkdf2_part = " + first_pbkdf2_part);
        log("second_pbkdf2_part = " + second_pbkdf2_part);

        return generate_nonce(start_value="django secure JS login").then(function(cnonce) {
            assert_length(cnonce, NONCE_LENGTH, "cnonce");

            log("second_pbkdf2_salt = cnonce + server_challenge");
            second_pbkdf2_salt = cnonce + challenge;
            log("second_pbkdf2_salt = " + second_pbkdf2_salt);

            log("pbkdf2_hash = pbkdf2(first_pbkdf2_part, salt=cnonce + server_challenge)");
            return pbkdf2(first_pbkdf2_part, second_pbkdf2_salt, ITERATIONS2).then(function(pbkdf2_hash) {
                log("pbkdf2_hash = " + pbkdf2_hash);
                log("result = pbkdf2_hash + $ + second_pbkdf2_part + $ + cnonce")
                var result = pbkdf2_hash + "$" + second_pbkdf2_part + "$" + cnonce;
                log("result = " + result);
                return result
            });
        });
    });
}


//-----------------------------------------------------------------------------

var digits="0123456789";
var ascii_lowercase = "abcdefghijklmnopqrstuvwxyz".toLowerCase();
var ascii_uppercase = ascii_lowercase.toUpperCase();
var test_string = " " + digits + ascii_lowercase + ascii_uppercase;


function test_sha_js() {
    log("Check sha...");
    return sha512_hexdigest(test_string).then(function (test_sha) {
        var should_be = "a65e0af3515b50f5edb593496634255e6599ba66a3fd0d08f26db4bd3b14d9c2b4c3b7cd64ed450ba023b1dcd5a797313aa5df6a1cf11a18f8c0fde523fffc2f";
        if (test_sha != should_be) {
            throw "sha test failed!\n'" + test_sha + "' != '" + should_be + "'";
        }
        log("Check the sha functions is ok.");
    });
}


function check_webcrypto() {
    window.crypto = window.crypto || window.msCrypto; // IE11 has msCrypto
    if (window.crypto.webkitSubtle) {  // Safari
        window.crypto.subtle = window.crypto.webkitSubtle;
    }
    if (!window.crypto) {
        throw "ERROR: browser does not support Web Cryptography API!";
    }
    log("Check Web Cryptography API is ok.");
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

    check_webcrypto();

    return test_sha_js().then(function() {
        return test_pbkdf2_js().then(function() {
            precheck_secure=true;
        })
    });
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

var ID_FORM="#login-form";
var ID_USERNAME="#id_username";
var ID_PASSWORD="#id_password";
var ID_OTP_TOKEN="#id_otp_token";
function init_secure_login() {
    /*
        Secure-JS-Login
        init from /secure_js_login/sha_form.html
    */
    $("#content-main").append('<p id="init_message">init...</p>');

    log("secure_js_login.js - init_secure_login()");
    
    try {
        precheck_secure_login().then(function() {
            log("precheck ok.");
  			$("#init_message").slideUp();
			$("form").slideDown();

			if ($(ID_USERNAME).val() == "") {
				$(ID_USERNAME).focus();
			} else if ($(ID_PASSWORD).val() == "") {
				$(ID_PASSWORD).focus();
			} else {
				$(ID_OTP_TOKEN).focus();
			}
        });
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
                calculate_hashes(password, salt, challenge).then(function(result) {
                    $(ID_PASSWORD).val(result);
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
