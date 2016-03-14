<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Authentication Plugin: clef Authentication
 * Just does a simple check against the moodle database.
 *
 * @package    auth_clef
 * @copyright  1999 onwards Martin Dougiamas (http://dougiamas.com)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir.'/authlib.php');
require_once($CFG->dirroot . '/auth/clef/lib.php');
require_once($CFG->dirroot . '/auth/clef/classes/Clef.php');
/**
 * clef authentication plugin.
 *
 * @package    auth
 * @subpackage clef
 * @copyright  1999 onwards Martin Dougiamas (http://dougiamas.com)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class auth_plugin_clef extends auth_plugin_base {

    /**
     * The name of the component. Used by the configuration.
     */
    const COMPONENT_NAME = 'auth_clef';
    const LEGACY_COMPONENT_NAME = 'auth/clef';

    /**
     * Constructor.
     */
    public function __construct() {
        $this->authtype = 'clef';
        $config = get_config(self::COMPONENT_NAME);
        $legacyconfig = get_config(self::LEGACY_COMPONENT_NAME);
        $this->config = (object)array_merge((array)$legacyconfig, (array)$config);
    }

    /**
     * Old syntax of class constructor. Deprecated in PHP7.
     *
     * @deprecated since Moodle 3.1
     */
    public function auth_plugin_clef() {
        debugging('Use of class name as constructor is deprecated', DEBUG_DEVELOPER);
        self::__construct();
    }

    /**
     * Returns true if the username and password work and false if they are
     * wrong or don't exist. (Non-mnet accounts only!)
     *
     * @param string $username The username
     * @param string $password The password
     * @return bool Authentication success or failure.
     */
    function user_login($username, $password) {
        global $CFG, $DB, $USER;
        if (!$user = $DB->get_record('user', array('username'=>$username, 'mnethostid'=>$CFG->mnet_localhost_id))) {
            return false;
        }
        if (!validate_internal_user_password($user, $password)) {
            return false;
        }
        if ($password === 'changeme') {
            // force the change - this is deprecated and it makes sense only for clef auth,
            // because most other plugins can not change password easily or
            // passwords are always specified by users
            set_user_preference('auth_forcepasswordchange', true, $user->id);
        }
        return true;
    }

    /**
     * Updates the user's password.
     *
     * Called when the user password is updated.
     *
     * @param  object  $user        User table object
     * @param  string  $newpassword Plaintext password
     * @return boolean result
     */
    function user_update_password($user, $newpassword) {
        $user = get_complete_user_data('id', $user->id);
        set_user_preference('auth_clef_passwordupdatetime', time(), $user->id);
        // This will also update the stored hash to the latest algorithm
        // if the existing hash is using an out-of-date algorithm (or the
        // legacy md5 algorithm).
        return update_internal_user_password($user, $newpassword);
    }

    function prevent_local_passwords() {
        return false;
    }

    /**
     * Returns true if this authentication plugin is 'internal'.
     *
     * @return bool
     */
    function is_internal() {
        return true;
    }

    /**
     * Returns true if this authentication plugin can change the user's
     * password.
     *
     * @return bool
     */
    function can_change_password() {
        return true;
    }

    /**
     * Returns the URL for changing the user's pw, or empty if the default can
     * be used.
     *
     * @return moodle_url
     */
    function change_password_url() {
        return null;
    }

    /**
     * Returns true if plugin allows resetting of internal password.
     *
     * @return bool
     */
    function can_reset_password() {
        return true;
    }

    /**
     * Returns true if plugin can be manually set.
     *
     * @return bool
     */
    function can_be_manually_set() {
        return true;
    }

    /**
     * Prints a form for configuring this authentication plugin.
     *
     * This function is called from admin/auth.php, and outputs a full page with
     * a form for configuring this plugin.
     *
     * @param array $config An object containing all the data for this page.
     * @param string $error
     * @param array $user_fields
     * @return void
     */
    function config_form($config, $err, $user_fields) {
        include 'config.html';
    }

    /**
     * Return number of days to user password expires.
     *
     * If user password does not expire, it should return 0 or a positive value.
     * If user password is already expired, it should return negative value.
     *
     * @param mixed $username username (with system magic quotes)
     * @return integer
     */
    public function password_expire($username) {
        $result = 0;

        if (!empty($this->config->expirationtime)) {
            $user = core_user::get_user_by_username($username, 'id,timecreated');
            $lastpasswordupdatetime = get_user_preferences('auth_clef_passwordupdatetime', $user->timecreated, $user->id);
            $expiretime = $lastpasswordupdatetime + $this->config->expirationtime * DAYSECS;
            $now = time();
            $result = ($expiretime - $now) / DAYSECS;
            if ($expiretime > $now) {
                $result = ceil($result);
            } else {
                $result = floor($result);
            }
        }

        return $result;
    }
    public function pre_loginpage_hook()
    {
        global $DB,$CFG,$SESSION;
        if($username = $_GET['username'])
        {
             $user = $DB->get_record('user',array('username'=>$username));
             //echo "Ok I have to try and log you in";
            $user = complete_user_login($user);
            $urltogo =  $SESSION->wantsurl ?  $SESSION->wantsurl : $CFG->wwwroot.'/';
             redirect($urltogo);
        }
    }
    /**
     * Authentication hook - is called every time user hit the login page
     * The code is run only if the param code is mentionned.
     */
    public function loginpage_hook() {

        global $PAGE, $CFG;
        define('APP_ID','791cf7f5affd514d6a5d5c40da9a1f3d');
        define('APP_SECRET','3c2ea313947afc8d9dad4601fd65276f');
# In your redirect URL endpoint:
        \Clef\Clef::initialize(APP_ID, APP_SECRET);

// Get the state parameter passed as a query arg and verify it
        if($_GET["state"]) {
        assert_state_is_valid($_GET["state"]);
       //die("Here");
// Get user information using the authorization code passed as a query arg
        try {
            $response = \Clef\Clef::get_login_information($_GET["code"]);
            die(print_object($response));
            $user_information = $response->info;
            
        } catch (Exception $e) {
            // An error occurred while trying to get user information
            echo "Login with Clef failed: " . $e->getMessage();
        } 
        }
        $PAGE->requires->jquery();
        $state = generate_state_parameter();
        $content =  '<script></script><script type="text/javascript" src="https://clef.io/v3/clef.js"
        class="clef-button"
        data-app-id="791cf7f5affd514d6a5d5c40da9a1f3d"
        data-color="blue"
        data-style="flat"
        data-state="'.$state.'"
        data-redirect-url="http://localhost/clef/clef.php"
        data-type="login">
</script><script></script>';
        //$content = "as";
        $PAGE->requires->js_init_code("buttonsCodeClef = '$content';");
        $PAGE->requires->js(new moodle_url($CFG->wwwroot . "/auth/clef/script.js"));
    }
    /**
     * Processes and stores configuration data for this authentication plugin.
     *
     * @param stdClass $config
     * @return void
     */
    function process_config($config) {
        // Set to defaults if undefined.
        if (!isset($config->expiration)) {
            $config->expiration = '';
        }
        if (!isset($config->expiration_warning)) {
            $config->expiration_warning = '';
        }
        if (!isset($config->expirationtime)) {
            $config->expirationtime = '';
        }

        // Save settings.
        set_config('expiration', $config->expiration, self::COMPONENT_NAME);
        set_config('expiration_warning', $config->expiration_warning, self::COMPONENT_NAME);
        set_config('expirationtime', $config->expirationtime, self::COMPONENT_NAME);
        return true;
    }

   /**
    * Confirm the new user as registered. This should normally not be used,
    * but it may be necessary if the user auth_method is changed to clef
    * before the user is confirmed.
    *
    * @param string $username
    * @param string $confirmsecret
    */
    function user_confirm($username, $confirmsecret = null) {
        global $DB;

        $user = get_complete_user_data('username', $username);

        if (!empty($user)) {
            if ($user->confirmed) {
                return AUTH_CONFIRM_ALREADY;
            } else {
                $DB->set_field("user", "confirmed", 1, array("id"=>$user->id));
                return AUTH_CONFIRM_OK;
            }
        } else  {
            return AUTH_CONFIRM_ERROR;
        }
    }

}


