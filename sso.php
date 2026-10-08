<?php
/**
 * Plugin Name: SSO
 * Author: Garth Mortensen, Mike Hansen, Micah Wood
 * Version: 0.7
 * License: GPLv2 or later
 * License URI: http://www.gnu.org/licenses/gpl-2.0.html
 */

if ( ! defined( 'SSO_REDIRECT_GUARD_KEY' ) ) {
    define( 'SSO_REDIRECT_GUARD_KEY', 'newfold_sso_pending_redirect_' );
}

if ( ! defined( 'SSO_REDIRECT_GUARD_TTL' ) ) {
    define( 'SSO_REDIRECT_GUARD_TTL', 120 );
}

if ( ! defined( 'SSO_LEGACY_ACTION' ) ) {
    define( 'SSO_LEGACY_ACTION', 'sso-check' );
}

if ( ! defined( 'SSO_TOKEN_ACTION' ) ) {
    define( 'SSO_TOKEN_ACTION', 'newfold_sso_login' );
}

if ( ! defined( 'SSO_TOKEN_META_KEY' ) ) {
    define( 'SSO_TOKEN_META_KEY', 'newfold_sso_token' );
}

if ( ! defined( 'SSO_TOKEN_TTL' ) ) {
    define( 'SSO_TOKEN_TTL', 600 );
}

if ( ! defined( 'SSO_HOSTING_LOGIN_FILTER' ) ) {
    define( 'SSO_HOSTING_LOGIN_FILTER', 'newfold/sso/hosting_login' );
}

if( ! function_exists( 'sso_debug' ) ){
    /**
     * Notify a separate must-use plugin that an SSO step happened.
     *
     * sso.php is replaced on every control-panel login, so debug logging
     * belongs in another file that listens for this hook.
     *
     * @param string $event   Step name.
     * @param array  $context Non-secret details. Never includes nonce, salt, or token.
     */
    function sso_debug( $event, $context = array() ){
        do_action( 'newfold_sso_debug', $event, $context );
    }
}

if( ! function_exists( 'sso_module_loaded' ) ){
    /**
     * Whether wp-module-sso is active on this site and already provides
     * the REST route, CLI command, and login screen output.
     *
     * @return bool
     */
    function sso_module_loaded(){
        return defined( 'NFD_SSO_DIR' );
    }
}

if( ! function_exists( 'sso_get_query' ) ){
    /**
     * Read the query string without WordPress's added slashes.
     *
     * WordPress slashes $_GET after plugins load. The early handler runs
     * before that, so only unslash once `init` has fired.
     *
     * @return array
     */
    function sso_get_query(){
        return did_action( 'init' ) ? wp_unslash( $_GET ) : $_GET;
    }
}

if( ! function_exists( 'sso_query_arg' ) ){
    /**
     * @param string $key Query parameter.
     *
     * @return string Empty string when missing or not a scalar.
     */
    function sso_query_arg( $key ){
        $query = sso_get_query();
        if ( ! isset( $query[ $key ] ) || ! is_scalar( $query[ $key ] ) ){
            return '';
        }
        return (string) $query[ $key ];
    }
}

if( ! function_exists( 'sso_check' ) ){
    /**
     * Handle a legacy `sso-check` login (nonce + salt hashed against the
     * `sso_token` transient or option).
     */
    function sso_check(){
        sso_debug( 'check_start', array(
            'flow'       => 'legacy',
            'has_nonce'  => '' !== sso_query_arg( 'nonce' ),
            'has_salt'   => '' !== sso_query_arg( 'salt' ),
            'has_user'   => '' !== sso_query_arg( 'user' ),
            'has_bounce' => '' !== sso_query_arg( 'bounce' ) || '' !== sso_query_arg( 'redirect' ),
        ) );

        $nonce = esc_attr( sso_query_arg( 'nonce' ) );
        $salt  = esc_attr( sso_query_arg( 'salt' ) );

        if ( '' === $nonce || '' === $salt ){
            sso_debug( 'missing_credentials', array( 'flow' => 'legacy' ) );
            sso_req_login();
        }
        if ( sso_check_blocked() ){
            sso_debug( 'blocked', array(
                'flow'     => 'legacy',
                'attempts' => (int) get_transient( sso_get_attempt_id() ),
            ) );
            sso_fail();
        }

        $has_epoch = preg_match( '/-e(\d+)$/', $nonce, $epoch );
        $expired   = ( $has_epoch && ( time() - $epoch[1] ) > 300 );

        $hash = substr( base64_encode( hash( 'sha256', $nonce . $salt, false ) ), 0, 64 );

        $token       = get_transient( 'sso_token' );
        $from_option = false;
        if ( false === $token ){
            $token       = get_option( 'sso_token' );
            $from_option = ( false !== $token );
        }

        if ( $expired || ! is_string( $token ) || ! hash_equals( $token, $hash ) ){
            sso_debug( 'token_invalid', array(
                'flow'        => 'legacy',
                'expired'     => (bool) $expired,
                'token_found' => ( false !== $token && '' !== $token ),
                'from_option' => $from_option,
            ) );
            sso_fail();
        }

        // Single use: clear both stores the token may live in.
        delete_transient( 'sso_token' );
        delete_option( 'sso_token' );

        $user = sso_get_legacy_user();
        if ( ! $user ){
            sso_debug( 'user_not_found', array( 'flow' => 'legacy' ) );
            sso_fail();
        }

        sso_login_user( $user, 'legacy', array( 'from_option' => $from_option ) );
    }
}

if( ! function_exists( 'sso_get_legacy_user' ) ){
    /**
     * Resolve the `user` query parameter (ID or email). Without one, use
     * the first administrator.
     *
     * @return WP_User|false
     */
    function sso_get_legacy_user(){
        $reference = sso_query_arg( 'user' );

        if ( '' !== $reference ){
            if ( is_email( $reference ) ){
                $user = get_user_by( 'email', sanitize_email( $reference ) );
            }else{
                $user = get_user_by( 'id', absint( $reference ) );
            }
            return is_a( $user, 'WP_User' ) ? $user : false;
        }

        $users = get_users( array( 'role' => 'administrator', 'number' => 1 ) );
        if ( isset( $users[0] ) && is_a( $users[0], 'WP_User' ) ){
            return $users[0];
        }

        return false;
    }
}

if( ! function_exists( 'sso_token_check' ) ){
    /**
     * Handle a `newfold_sso_login` login (per-user token stored in user meta,
     * issued by the REST endpoint).
     */
    function sso_token_check(){
        $token = htmlspecialchars( strip_tags( sso_query_arg( 'token' ) ) );

        sso_debug( 'check_start', array(
            'flow'       => 'token',
            'has_token'  => '' !== $token,
            'has_bounce' => '' !== sso_query_arg( 'bounce' ) || '' !== sso_query_arg( 'redirect' ),
        ) );

        if ( '' === $token ){
            sso_debug( 'missing_credentials', array( 'flow' => 'token' ) );
            sso_req_login();
        }
        if ( sso_check_blocked() ){
            sso_debug( 'blocked', array(
                'flow'     => 'token',
                'attempts' => (int) get_transient( sso_get_attempt_id() ),
            ) );
            sso_fail();
        }

        $reason = sso_validate_token( $token );
        if ( true !== $reason ){
            sso_debug( 'token_invalid', array(
                'flow'   => 'token',
                'reason' => $reason,
            ) );
            sso_fail();
        }

        $user = get_user_by( 'id', sso_get_user_id_from_token( $token ) );
        delete_user_meta( $user->ID, SSO_TOKEN_META_KEY );

        sso_login_user( $user, 'token' );
    }
}

if( ! function_exists( 'sso_generate_token' ) ){
    /**
     * @param int $user_id User the token logs in as.
     *
     * @return string
     */
    function sso_generate_token( $user_id ){
        return base64_encode(
            implode(
                ':',
                array(
                    (int) $user_id,
                    time(),
                    wp_generate_password( 64, true, true ),
                )
            )
        );
    }
}

if( ! function_exists( 'sso_save_token' ) ){
    /**
     * @param string $token Token from sso_generate_token().
     */
    function sso_save_token( $token ){
        update_user_meta( sso_get_user_id_from_token( $token ), SSO_TOKEN_META_KEY, $token );
    }
}

if( ! function_exists( 'sso_get_user_id_from_token' ) ){
    /**
     * @param string $token SSO token.
     *
     * @return int
     */
    function sso_get_user_id_from_token( $token ){
        $parts = explode( ':', (string) base64_decode( $token ), 3 );
        return absint( array_shift( $parts ) );
    }
}

if( ! function_exists( 'sso_validate_token' ) ){
    /**
     * @param string $token SSO token.
     *
     * @return true|string True when valid, otherwise the failure reason.
     */
    function sso_validate_token( $token ){
        $parts = explode( ':', (string) base64_decode( $token ), 3 );

        $user_id = absint( array_shift( $parts ) );
        if ( ! $user_id ){
            return 'malformed';
        }

        $user = get_user_by( 'id', $user_id );
        if ( ! is_a( $user, 'WP_User' ) ){
            return 'user_not_found';
        }

        $time = (int) array_shift( $parts );
        if ( ! $time || ( $time + SSO_TOKEN_TTL ) < time() ){
            return 'expired';
        }

        $stored = get_user_meta( $user->ID, SSO_TOKEN_META_KEY, true );
        if ( ! is_string( $stored ) || '' === $stored || ! hash_equals( $stored, $token ) ){
            return 'mismatch';
        }

        return true;
    }
}

if( ! function_exists( 'sso_login_user' ) ){
    /**
     * Log the user in, fire the success hooks, and redirect.
     *
     * @param WP_User $user    User to log in.
     * @param string  $flow    `legacy` or `token`.
     * @param array   $context Extra debug context.
     */
    function sso_login_user( $user, $flow, $context = array() ){
        if ( preg_match( "/['\"\\\\<|]/", $user->user_login ) ){
            sso_debug( 'invalid_username', array(
                'flow'    => $flow,
                'user_id' => (int) $user->ID,
            ) );
            sso_fail( 'invalid_username' );
        }

        wp_set_current_user( $user->ID, $user->user_login );
        wp_set_auth_cookie( $user->ID );

        $redirect = wp_validate_redirect( sso_get_success_url(), admin_url() );

        // Pin before wp_login so an onboarding plugin cannot hijack
        // this request, and persist a short-lived transient so the
        // landing admin_init can re-pin the next request.
        sso_pin_redirect( $redirect );
        set_transient(
            SSO_REDIRECT_GUARD_KEY . $user->ID,
            $redirect,
            sso_get_redirect_guard_ttl()
        );

        sso_debug( 'success', array_merge( array(
            'flow'     => $flow,
            'user_id'  => (int) $user->ID,
            'redirect' => $redirect,
        ), $context ) );

        do_action( 'wp_login', $user->user_login, $user );

        if ( has_action( 'eig_sso_success' ) ){
            do_action( 'eig_sso_success', $user, $redirect );
        }
        do_action( 'newfold_sso_success', $user, $redirect );

        wp_safe_redirect( $redirect );
        exit;
    }
}

if( ! function_exists( 'sso_get_success_url' ) ){
    /**
     * Admin URL from `bounce` (or `redirect`), keeping any non-SSO query
     * parameters. Falls back to the dashboard.
     *
     * @return string
     */
    function sso_get_success_url(){
        $url = '';

        foreach ( array( 'bounce', 'redirect' ) as $param ){
            $path = sso_query_arg( $param );
            if ( '' !== $path ){
                $url = admin_url( $path );
                break;
            }
        }

        if ( $url ){
            $params = sso_get_query();
            foreach ( array( 'action', 'bounce', 'nonce', 'redirect', 'salt', 'token', 'user' ) as $key ){
                unset( $params[ $key ] );
            }
            if ( ! empty( $params ) ){
                $url = add_query_arg( urlencode_deep( $params ), $url );
            }
        }else{
            $url = apply_filters( 'newfold_sso_success_url_default', admin_url() );
        }

        if ( has_filter( 'eig_sso_redirect' ) ){
            $url = (string) apply_filters( 'eig_sso_redirect', $url );
        }

        return (string) apply_filters( 'newfold_sso_success_url', $url );
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
                sso_debug( 'redirect_hijacked', array(
                    'from' => (string) $location,
                    'to'   => (string) $url,
                ) );
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
        sso_debug( 'landing_guard_finished', array(
            'kept' => (bool) $hijacked,
        ) );

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
            sso_debug( 'landing_guard_invalid', array(
                'user_id' => (int) $user_id,
            ) );
            return;
        }

        $GLOBALS['sso_redirect_guard_key'] = $key;
        sso_debug( 'landing_guard', array(
            'user_id'  => (int) $user_id,
            'redirect' => $redirect,
        ) );
        sso_pin_redirect( $redirect );

        add_action( 'shutdown', 'sso_consume_redirect_guard_if_clean', PHP_INT_MAX );
    }
}

if( ! function_exists( 'sso_maybe_run_early' ) ){
    /**
     * Handle `sso-check` before regular plugins load.
     *
     * `newfold_sso_login` is left to admin-ajax.php so brand plugins can
     * still filter the destination (`newfold_sso_success_url_default`).
     */
    function sso_maybe_run_early(){
        if ( ! isset( $_GET['action'] ) || SSO_LEGACY_ACTION !== $_GET['action'] ){
            return;
        }
        sso_debug( 'early_start', array( 'action' => SSO_LEGACY_ACTION ) );
        if ( ! function_exists( 'wp_set_auth_cookie' ) ){
            require_once ABSPATH . WPINC . '/pluggable.php';
        }
        // wp-settings.php defines the cookie constants after muplugins_loaded;
        // wp_set_auth_cookie() fatals without them.
        if ( ! defined( 'AUTH_COOKIE' ) ){
            if ( is_multisite() && function_exists( 'ms_cookie_constants' ) ){
                ms_cookie_constants();
            }
            wp_cookie_constants();
        }
        sso_check();
    }
}

if( ! function_exists( 'sso_req_login' ) ){
    function sso_req_login(){
        wp_safe_redirect( wp_login_url() );
        exit;
    }
}

if( ! function_exists( 'sso_fail' ) ){
    /**
     * Count a failed attempt, fire the failure hooks, and send the user to
     * wp-login.php.
     *
     * @param string $error Optional error code shown on the login screen.
     */
    function sso_fail( $error = '' ){
        sso_add_failed_attempt();

        if ( has_action( 'eig_sso_fail' ) ){
            do_action( 'eig_sso_fail' );
        }
        do_action( 'newfold_sso_fail' );

        $url = wp_login_url();
        if ( '' !== $error ){
            $url = add_query_arg( 'error', $error, $url );
        }
        wp_safe_redirect( $url );
        exit;
    }
}

if( ! function_exists( 'sso_get_attempt_id' ) ){
    /**
     * Transient key for this client's failed-attempt count.
     *
     * Hashed because esc_url() returns an empty string for IPv6 addresses,
     * which made every IPv6 client share one counter.
     *
     * @return string
     */
    function sso_get_attempt_id(){
        $ip = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '';
        return 'sso_attempts_' . md5( $ip );
    }
}

if( ! function_exists( 'sso_add_failed_attempt' ) ){
    function sso_add_failed_attempt(){
        $attempts = (int) get_transient( sso_get_attempt_id() );
        $attempts ++;
        set_transient( sso_get_attempt_id(), $attempts, 300 );
    }
}

if( ! function_exists( 'sso_check_blocked' ) ){
    function sso_check_blocked(){
        return (int) get_transient( sso_get_attempt_id() ) > 4;
    }
}

if( ! function_exists( 'sso_build_login_url' ) ){
    /**
     * @param array $params Query parameters for admin-ajax.php.
     *
     * @return string
     */
    function sso_build_login_url( $params ){
        return admin_url( '/admin-ajax.php' ) . '?' . http_build_query( $params );
    }
}

if( ! function_exists( 'sso_register_rest_routes' ) ){
    function sso_register_rest_routes(){
        if ( sso_module_loaded() ){
            return;
        }

        register_rest_route(
            'newfold-sso/v1',
            '/sso',
            array(
                array(
                    'methods'             => 'GET',
                    'callback'            => 'sso_rest_get_link',
                    'permission_callback' => 'sso_rest_permission',
                ),
            )
        );
    }
}

if( ! function_exists( 'sso_rest_permission' ) ){
    /**
     * @return true|WP_Error
     */
    function sso_rest_permission(){
        if ( ! current_user_can( 'read' ) ){
            return new WP_Error(
                'rest_forbidden_context',
                __( 'Sorry, you are not allowed to access this endpoint.', 'wp-module-sso' ),
                array( 'status' => rest_authorization_required_code() )
            );
        }
        return true;
    }
}

if( ! function_exists( 'sso_rest_get_link' ) ){
    /**
     * Issue a single-use login link for the current user.
     *
     * @return WP_REST_Response
     */
    function sso_rest_get_link(){
        $user_id = get_current_user_id();
        $token   = sso_generate_token( $user_id );
        sso_save_token( $token );

        sso_debug( 'link_created', array(
            'source'     => 'rest',
            'flow'       => 'token',
            'user_id'    => (int) $user_id,
            'expires_in' => SSO_TOKEN_TTL,
        ) );

        return rest_ensure_response(
            sso_build_login_url( array(
                'action' => SSO_TOKEN_ACTION,
                'token'  => $token,
            ) )
        );
    }
}

if( ! function_exists( 'sso_cli_command' ) ){
    /**
     * Single sign-on via WP-CLI. Prints a single-use login link.
     *
     * ## OPTIONS
     *
     * [--username=<username>]
     * : Log in as the user with this login.
     *
     * [--email=<email>]
     * : Log in as the user with this email.
     *
     * [--id=<id>]
     * : Log in as the user with this ID.
     *
     * [--role=<role>]
     * : Log in as the first user with this role. Defaults to administrator.
     *
     * [--min=<minutes>]
     * : Minutes until the link expires. Default 3.
     *
     * [--url-only]
     * : Print only the URL.
     *
     * @param array $args       Unused.
     * @param array $assoc_args Options above.
     */
    function sso_cli_command( $args, $assoc_args ){
        unset( $args );

        $expiry_min = isset( $assoc_args['min'] ) ? max( 1, (int) $assoc_args['min'] ) : 3;
        $salt       = wp_generate_password( 32, false );
        $nonce      = wp_create_nonce( 'newfold-sso' );
        $hash       = substr( base64_encode( hash( 'sha256', $nonce . $salt, false ) ), 0, 64 );

        $params = array(
            'action' => SSO_LEGACY_ACTION,
            'salt'   => $salt,
            'nonce'  => $nonce,
        );

        $user = false;
        if ( isset( $assoc_args['role'] ) ){
            $role  = is_string( $assoc_args['role'] ) && '' !== $assoc_args['role'] ? $assoc_args['role'] : 'administrator';
            $users = get_users( array( 'role' => $role, 'number' => 1 ) );
            if ( isset( $users[0] ) ){
                $user = $users[0];
            }
        }
        if ( isset( $assoc_args['email'] ) ){
            $user = get_user_by( 'email', $assoc_args['email'] );
        }
        if ( isset( $assoc_args['username'] ) ){
            $user = get_user_by( 'login', $assoc_args['username'] );
        }
        if ( isset( $assoc_args['id'] ) ){
            $user = get_user_by( 'id', (int) $assoc_args['id'] );
        }
        if ( is_a( $user, 'WP_User' ) ){
            $params['user'] = $user->ID;
        }

        set_transient( 'sso_token', $hash, MINUTE_IN_SECONDS * $expiry_min );

        sso_debug( 'link_created', array(
            'source'     => 'cli',
            'flow'       => 'legacy',
            'user_id'    => isset( $params['user'] ) ? (int) $params['user'] : 0,
            'expires_in' => MINUTE_IN_SECONDS * $expiry_min,
        ) );

        $link = sso_build_login_url( $params );

        if ( isset( $assoc_args['url-only'] ) ){
            WP_CLI::log( $link );
            return;
        }

        /* translators: %d: number of minutes */
        WP_CLI::success( sprintf( __( 'Single-use login link valid for %d minutes', 'wp-module-sso' ), $expiry_min ) );
        WP_CLI::log( WP_CLI::colorize( '%U' . $link . '%n' ) );
    }
}

if( ! function_exists( 'sso_register_cli_command' ) ){
    function sso_register_cli_command(){
        if ( sso_module_loaded() ){
            return;
        }

        WP_CLI::add_command(
            'newfold sso',
            'sso_cli_command',
            array(
                'shortdesc' => 'Single sign-on functionality for WordPress.',
                'longdesc'  => 'Handle single sign-on from Newfold hosting platforms and get magic link.' .
                    PHP_EOL . 'Associative Args: --username --role --email --id --min=MINUTES_UNTIL_EXPIRE --url-only',
            )
        );
    }
}

if( ! function_exists( 'sso_login_message' ) ){
    /**
     * Explain an SSO failure on wp-login.php.
     *
     * @param string $message Existing login message.
     *
     * @return string
     */
    function sso_login_message( $message ){
        if ( sso_module_loaded() ){
            return $message;
        }

        $error = isset( $_GET['error'] ) ? sanitize_key( $_GET['error'] ) : '';
        if ( 'invalid_username' !== $error ){
            return $message;
        }

        $text = __( 'SSO failed: username cannot contain invalid characters.', 'wp-module-sso' );

        return $message . "<div class='login-error' style='color: red; font-weight: bold;'>" . esc_html( $text ) . '</div>';
    }
}

if( ! function_exists( 'sso_get_hosting_login_config' ) ){
    /**
     * Config for the "Login with <Host>" button, set by a brand plugin via
     * the `newfold/sso/hosting_login` filter:
     *   enabled (bool), url (string), label (string), icon_svg (string),
     *   new_tab (bool), accent_color (string).
     *
     * @return array|null Null when disabled, incomplete, or the module renders it.
     */
    function sso_get_hosting_login_config(){
        if ( sso_module_loaded() ){
            return null;
        }

        $defaults = array(
            'enabled'      => false,
            'url'          => '',
            'label'        => '',
            'icon_svg'     => '',
            'new_tab'      => false,
            'accent_color' => '',
        );

        $config = array_merge( $defaults, (array) apply_filters( SSO_HOSTING_LOGIN_FILTER, $defaults ) );

        if ( empty( $config['enabled'] ) || empty( $config['url'] ) || empty( $config['label'] ) ){
            return null;
        }

        return $config;
    }
}

if( ! function_exists( 'sso_hosting_login_styles' ) ){
    function sso_hosting_login_styles(){
        if ( null === sso_get_hosting_login_config() ){
            return;
        }
        ?>
<style id="nfd-sso-hosting-login-css">
#loginform{display:flex;flex-direction:column}
.nfd-sso-hosting-login{order:99;margin:12px 0 0}
.nfd-sso-hosting-login *,.nfd-sso-hosting-login *::before,.nfd-sso-hosting-login *::after{box-sizing:border-box}
.nfd-sso-hosting-login__divider{margin-bottom:16px;position:relative;text-align:center}
.nfd-sso-hosting-login__divider::before{background:#dcdcde;content:"";height:1px;position:absolute;left:0;top:50%;width:100%}
.nfd-sso-hosting-login__divider span{background:#fff;color:#777;position:relative;padding:0 8px;text-transform:uppercase}
.nfd-sso-hosting-login__button{display:flex;align-items:center;justify-content:center;gap:12px;width:100%;min-height:48px;padding:12px 20px;background:var(--nfd-sso-hosting-login-accent,#2271b1);color:#fff;border:1px solid var(--nfd-sso-hosting-login-accent,#2271b1);border-radius:4px;text-decoration:none;font-family:inherit;font-size:15px;font-weight:500;line-height:1;letter-spacing:.01em;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;cursor:pointer;transition:background-color 120ms ease,box-shadow 120ms ease,transform 120ms ease}
.nfd-sso-hosting-login__button:hover{color:#fff;background:color-mix(in srgb,var(--nfd-sso-hosting-login-accent,#2271b1) 90%,#000);border-color:color-mix(in srgb,var(--nfd-sso-hosting-login-accent,#2271b1) 90%,#000)}
.nfd-sso-hosting-login__button:focus,.nfd-sso-hosting-login__button:focus-visible{color:#fff;outline:none;box-shadow:0 0 0 2px #fff,0 0 0 4px var(--nfd-sso-hosting-login-accent,#2271b1)}
.nfd-sso-hosting-login__button:active{transform:translateY(1px)}
.nfd-sso-hosting-login__icon{display:inline-flex;flex:0 0 auto;width:16px;height:16px;color:#fff}
.nfd-sso-hosting-login__icon svg{width:100%;height:100%;fill:currentColor;display:block}
.nfd-sso-hosting-login__label{display:inline-block}
</style>
        <?php
    }
}

if( ! function_exists( 'sso_hosting_login_allowed_svg' ) ){
    /**
     * @return array wp_kses() rules for the button icon.
     */
    function sso_hosting_login_allowed_svg(){
        return array(
            'svg'    => array( 'class' => true, 'fill' => true, 'height' => true, 'stroke' => true, 'stroke-width' => true, 'viewbox' => true, 'width' => true, 'xmlns' => true ),
            'g'      => array( 'fill' => true, 'stroke' => true, 'stroke-miterlimit' => true, 'stroke-width' => true, 'transform' => true ),
            'path'   => array( 'd' => true, 'fill' => true, 'opacity' => true, 'stroke' => true, 'stroke-linecap' => true, 'stroke-linejoin' => true, 'stroke-width' => true, 'transform' => true ),
            'rect'   => array( 'fill' => true, 'height' => true, 'rx' => true, 'transform' => true, 'width' => true, 'x' => true, 'y' => true ),
            'circle' => array( 'cx' => true, 'cy' => true, 'fill' => true, 'r' => true ),
            'text'   => array( 'fill' => true, 'font-family' => true, 'font-size' => true, 'font-weight' => true, 'transform' => true, 'x' => true, 'y' => true ),
        );
    }
}

if( ! function_exists( 'sso_hosting_login_render' ) ){
    function sso_hosting_login_render(){
        $config = sso_get_hosting_login_config();
        if ( null === $config ){
            return;
        }

        $style = '' !== (string) $config['accent_color']
            ? ' style="--nfd-sso-hosting-login-accent: ' . esc_attr( $config['accent_color'] ) . ';"'
            : '';
        $target = ! empty( $config['new_tab'] ) ? ' target="_blank" rel="noopener noreferrer"' : '';
        $icon   = '' !== (string) $config['icon_svg']
            ? '<span class="nfd-sso-hosting-login__icon" aria-hidden="true">' . wp_kses( $config['icon_svg'], sso_hosting_login_allowed_svg() ) . '</span>'
            : '';

        echo '<div class="nfd-sso-hosting-login"' . $style . '>'
            . '<div class="nfd-sso-hosting-login__divider"><span>' . esc_html__( 'or', 'wp-module-sso' ) . '</span></div>'
            . '<a class="nfd-sso-hosting-login__button" href="' . esc_url( $config['url'] ) . '"' . $target . '>'
            . $icon
            . '<span class="nfd-sso-hosting-login__label">' . esc_html( $config['label'] ) . '</span>'
            . '</a></div>';
    }
}

add_action( 'muplugins_loaded', 'sso_maybe_run_early', 0 );
add_action( 'admin_init', 'sso_guard_pending_redirect', PHP_INT_MIN );
add_action( 'wp_ajax_nopriv_' . SSO_LEGACY_ACTION, 'sso_check' );
add_action( 'wp_ajax_' . SSO_LEGACY_ACTION, 'sso_check' );
add_action( 'wp_ajax_nopriv_' . SSO_TOKEN_ACTION, 'sso_token_check' );
add_action( 'wp_ajax_' . SSO_TOKEN_ACTION, 'sso_token_check' );
add_action( 'rest_api_init', 'sso_register_rest_routes' );
add_action( 'cli_init', 'sso_register_cli_command' );
add_filter( 'login_message', 'sso_login_message' );
add_action( 'login_head', 'sso_hosting_login_styles' );
// Last so the button sits below other login_form output (e.g. external SSO providers).
add_action( 'login_form', 'sso_hosting_login_render', PHP_INT_MAX );
