<?php
    function base64url_encode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    function generate_state_parameter() {
        global $SESSION;
        if (isset($SESSION->state)) {
            return $SESSION->state;
        } else {
            $state = base64url_encode(openssl_random_pseudo_bytes(32));
            $SESSION->state = $state;
            return $state;
        }
}

function assert_state_is_valid($state) {
     global $SESSION;
    $is_valid = isset($SESSION->state) && strlen($SESSION->state) > 0 && $SESSION->state == $state;
    unset($SESSION->state);
    if (!$is_valid) {
        header('HTTP/1.0 403 Forbidden');
        echo "The state parameter didn't match what was passed in to the Clef button.";
        exit;
    }
    return $is_valid;
}