<?php
/**
 * Plugin Name: SSO
 * Author: Garth Mortensen, Mike Hansen, Micah Wood
 * Version: 0.6
 * License: GPLv2 or later
 * License URI: http://www.gnu.org/licenses/gpl-2.0.html
 */

if ( ! defined( 'SSO_REDIRECT_GUARD_KEY' ) ) {
    define( 'SSO_REDIRECT_GUARD_KEY', 'newfold_sso_pending_redirect_' );
}

if ( ! defined( 'SSO_REDIRECT_GUARD_TTL' ) ) {
    define( 'SSO_REDIRECT_GUARD_TTL', 120 );
}

if( ! function_exists( 'sso_check' ) ){
    function sso_check(){
        if ( ! isset( $_GET['salt'] ) || ! isset( $_GET['nonce'] ) ){
            sso_req_login();
        }
        if ( sso_check_blocked() ){
            sso_req_login();
        }
        $nonce = esc_attr( $_GET['nonce'] );
        $salt  = esc_attr( $_GET['salt'] );
        $has_epoch = preg_match('/-e(\d+)$/', $nonce, $epoch);
        $expired = ( $has_epoch && (time() - $epoch[1]) > 300 ) ? true : false;

        if ( ! empty( $_GET['user'] ) ){
            $user = esc_attr( $_GET['user'] );
        }else{
            $user = get_users( array( 'role' => 'administrator', 'number' => 1 ) );
            if ( is_array( $user ) && is_a( $user[0], 'WP_User' ) ){
                $user = $user[0];
                $user = $user->ID;
            }else{
                $user = 0;
            }
        }
        $bounce = ! empty( $_GET['bounce'] ) ? $_GET['bounce'] : '';
        $hash   = base64_encode( hash( 'sha256', $nonce . $salt, false ) );
        $hash   = substr( $hash, 0, 64 );

        $token = get_transient( 'sso_token' );
        if ( $token === false ) {
            $token = get_option( 'sso_token' );
        }
        if ( ! $expired && $token == $hash ) {
            if ( is_email( $user ) ){
                $user = get_user_by( 'email', $user );
            }else{
                $user = get_user_by( 'id', (int) $user );
            }
            delete_option( 'sso_token' );
            if ( is_a( $user, 'WP_User' ) ){
                wp_set_current_user( $user->ID, $user->user_login );
                wp_set_auth_cookie( $user->ID );

                $redirect = wp_validate_redirect( admin_url( $bounce ), admin_url() );

                // Pin before wp_login so an onboarding plugin cannot hijack
                // this request, and persist a short-lived transient so the
                // landing admin_init can re-pin the next request.
                sso_pin_redirect( $redirect );
                set_transient(
                    SSO_REDIRECT_GUARD_KEY . $user->ID,
                    $redirect,
                    sso_get_redirect_guard_ttl()
                );

                do_action( 'wp_login', $user->user_login, $user );
                delete_transient( 'sso_token' );
                wp_safe_redirect( $redirect );
            }else{
                sso_req_login();
            }
        }else{
            sso_add_failed_attempt();
            sso_req_login();
        }
        die();
    }
}

if( ! function_exists( 'sso_get_redirect_guard_ttl' ) ){
    function sso_get_redirect_guard_ttl(){
        return max( 30, (int) apply_filters( 'newfold_sso_redirect_guard_ttl', SSO_REDIRECT_GUARD_TTL ) );
    }
}

if( ! function_exists( 'sso_pin_redirect' ) ){
    function sso_pin_redirect( $url ){
        if ( ! empty( $GLOBALS['sso_redirect_pin_callback'] ) ){
            remove_filter( 'wp_redirect', $GLOBALS['sso_redirect_pin_callback'], PHP_INT_MAX );
            $GLOBALS['sso_redirect_pin_callback'] = null;
        }

        $GLOBALS['sso_redirect_guard_hijacked'] = false;
        $GLOBALS['sso_redirect_pin_callback']   = static function ( $location, $status = 302 ) use ( $url ) {
            unset( $status );
            if ( (string) $location !== (string) $url ){
                $GLOBALS['sso_redirect_guard_hijacked'] = true;
            }

            return $url;
        };

        add_filter( 'wp_redirect', $GLOBALS['sso_redirect_pin_callback'], PHP_INT_MAX, 2 );
    }
}

if( ! function_exists( 'sso_consume_redirect_guard_if_clean' ) ){
    function sso_consume_redirect_guard_if_clean(){
        $key      = isset( $GLOBALS['sso_redirect_guard_key'] ) ? $GLOBALS['sso_redirect_guard_key'] : null;
        $hijacked = ! empty( $GLOBALS['sso_redirect_guard_hijacked'] );
        if ( $key && ! $hijacked ){
            delete_transient( $key );
            $GLOBALS['sso_redirect_guard_key'] = null;
        }
    }
}

if( ! function_exists( 'sso_guard_pending_redirect' ) ){
    function sso_guard_pending_redirect(){
        $user_id = get_current_user_id();
        if ( ! $user_id ){
            return;
        }

        $key      = SSO_REDIRECT_GUARD_KEY . $user_id;
        $redirect = get_transient( $key );
        if ( ! $redirect ){
            return;
        }

        $redirect = wp_validate_redirect( $redirect, false );
        if ( ! $redirect ){
            delete_transient( $key );
            return;
        }

        $GLOBALS['sso_redirect_guard_key'] = $key;
        sso_pin_redirect( $redirect );

        add_action( 'shutdown', 'sso_consume_redirect_guard_if_clean', PHP_INT_MAX );
    }
}

if( ! function_exists( 'sso_maybe_run_early' ) ){
    function sso_maybe_run_early(){
        if ( ! isset( $_GET['action'] ) || 'sso-check' !== $_GET['action'] ){
            return;
        }
        if ( ! function_exists( 'wp_set_auth_cookie' ) ){
            require_once ABSPATH . WPINC . '/pluggable.php';
        }
        sso_check();
    }
}

add_action( 'muplugins_loaded', 'sso_maybe_run_early', 0 );
add_action( 'admin_init', 'sso_guard_pending_redirect', PHP_INT_MIN );
add_action( 'wp_ajax_nopriv_sso-check', 'sso_check' );
add_action( 'wp_ajax_sso-check', 'sso_check' );

if( ! function_exists( 'sso_req_login' ) ){
    function sso_req_login(){
        wp_safe_redirect( wp_login_url() );
    }
}

if( ! function_exists( 'sso_get_attempt_id' ) ){
    function sso_get_attempt_id(){
        return 'sso' . esc_url( $_SERVER['REMOTE_ADDR'] );
    }
}

if( ! function_exists( 'sso_add_failed_attempt' ) ){
    function sso_add_failed_attempt(){
        $attempts = get_transient( sso_get_attempt_id(), 0 );
        $attempts ++;
        set_transient( sso_get_attempt_id(), $attempts, 300 );
    }
}

if( ! function_exists( 'sso_check_blocked' ) ){
    function sso_check_blocked(){
        $attempts = get_transient( sso_get_attempt_id(), 0 );
        if ( $attempts > 4 ){
            return true;
        }
        return false;
    }
}
