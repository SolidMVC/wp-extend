<?php
/**
 * S.O.L.I.D. MVC additional functions for Main WordPress Pluggable file.
 *
 * This is the file of functions, that is missing in wp-includes\pluggable.php
 *
 * @see \wp-includes\pluggable.php
 * @package WordPress
 */

if ( ! function_exists( 'wp_get_persistent_token' ) ) :
    /**
     * Function to get the client IP address
     * Purpose - an alternative to wp_get_session_token()
     *
     * @see wp_get_session_token
     * @return string
     */
    function wp_get_persistent_token() {
        if (isset($_SERVER['HTTP_CLIENT_IP'])) {
            $ip_address = $_SERVER['HTTP_CLIENT_IP'];
        } else if(isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip_address = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } else if(isset($_SERVER['HTTP_X_FORWARDED'])) {
            $ip_address = $_SERVER['HTTP_X_FORWARDED'];
        } else if(isset($_SERVER['HTTP_FORWARDED_FOR'])) {
            $ip_address = $_SERVER['HTTP_FORWARDED_FOR'];
        } else if(isset($_SERVER['HTTP_FORWARDED'])) {
            $ip_address = $_SERVER['HTTP_FORWARDED'];
        } else if(isset($_SERVER['REMOTE_ADDR'])) {
            $ip_address = $_SERVER['REMOTE_ADDR'];
        } else {
            $ip_address = 'UNKNOWN';
        }
        $token = crc32($ip_address);

        return $token;
    }
endif;

if ( ! function_exists( 'check_persistent_ajax_referer' ) ) :
    /**
     * Verifies the Ajax request to prevent processing requests external of the blog.
     *
     * @since 2.0.3
     *
     * @param int|string   $action    Action nonce.
     * @param false|string $query_arg Optional. Key to check for the nonce in `$_REQUEST` (since 2.5). If false,
     *                                `$_REQUEST` values will be evaluated for '_ajax_nonce', and '_wpnonce'
     *                                (in that order). Default false.
     * @param bool         $die       Optional. Whether to die early when the nonce cannot be verified.
     *                                Default true.
     * @return false|int False if the nonce is invalid, 1 if the nonce is valid and generated between
     *                   0-12 hours ago, 2 if the nonce is valid and generated between 12-24 hours ago.
     */
    function check_persistent_ajax_referer( $action = -1, $query_arg = false, $die = true ) {
        if ( -1 == $action ) {
            _doing_it_wrong( __FUNCTION__, __( 'You should specify a nonce action to be verified by using the first parameter.' ), '4.7' );
        }

        $nonce = '';

        if ( $query_arg && isset( $_REQUEST[ $query_arg ] ) ) {
            $nonce = $_REQUEST[ $query_arg ];
        } elseif ( isset( $_REQUEST['_ajax_nonce'] ) ) {
            $nonce = $_REQUEST['_ajax_nonce'];
        } elseif ( isset( $_REQUEST['_wpnonce'] ) ) {
            $nonce = $_REQUEST['_wpnonce'];
        }

        $result = wp_verify_persistent_nonce( $nonce, $action );

        /**
         * Fires once the Ajax request has been validated or not.
         *
         * @since 2.1.0
         *
         * @param string    $action The Ajax nonce action.
         * @param false|int $result False if the nonce is invalid, 1 if the nonce is valid and generated between
         *                          0-12 hours ago, 2 if the nonce is valid and generated between 12-24 hours ago.
         */
        do_action( 'check_persistent_ajax_referer', $action, $result );

        if ( $die && false === $result ) {
            if ( wp_doing_ajax() ) {
                wp_die( -1, 403 );
            } else {
                die( '-1' );
            }
        }

        return $result;
    }
endif;

if ( ! function_exists( 'wp_verify_persistent_nonce' ) ) :
    /**
     * Verify that correct nonce was used with time limit.
     *
     * The user is given an amount of time to use the token, so therefore, since the
     * USER_IP and $action remain the same, the independent variable is the time.
     *
     * @note For persistent nonce, user is not involved
     *
     * @since 2.0.3
     *
     * @param string     $nonce  Nonce that was used in the form to verify
     * @param string|int $action Should give context to what is taking place and be the same when nonce was created.
     * @return false|int False if the nonce is invalid, 1 if the nonce is valid and generated between
     *                   0-12 hours ago, 2 if the nonce is valid and generated between 12-24 hours ago.
     */
    function wp_verify_persistent_nonce( $nonce, $action = -1 ) {
        $nonce = (string) $nonce;

        if ( empty( $nonce ) ) {
            return false;
        }

        $token = wp_get_persistent_token();
        $i     = wp_nonce_tick();

        // Nonce generated 0-12 hours ago
        $expected = substr( wp_hash( $i . '|' . $action . '|' . $token, 'nonce' ), -12, 10 );
        if ( hash_equals( $expected, $nonce ) ) {
            return 1;
        }

        // Nonce generated 12-24 hours ago
        $expected = substr( wp_hash( ( $i - 1 ) . '|' . $action . '|' . $token, 'nonce' ), -12, 10 );
        if ( hash_equals( $expected, $nonce ) ) {
            return 2;
        }

        /**
         * Fires when persistent nonce verification fails.
         * @note $uid is not included here
         *
         * @since 4.4.0
         *
         * @param string     $nonce  The invalid nonce.
         * @param string|int $action The nonce action.
         * @param WP_User    $user   The current user object.
         * @param string     $token  The user's session token.
         */
        do_action( 'wp_verify_persistent_nonce_failed', $nonce, $action, $token );

        // Invalid nonce
        return false;
    }
endif;

if ( ! function_exists( 'wp_create_persistent_nonce' ) ) :
    /**
     * Creates a cryptographic token tied to a specific action, user, user session,
     * and window of time.
     *
     * @note For persistent nonce, user is not involved
     *
     * @since 2.0.3
     * @since 4.0.0 Session tokens were integrated with nonce creation
     *
     * @param string|int $action Scalar value to add context to the nonce.
     * @return string The token.
     */
    function wp_create_persistent_nonce( $action = -1 ) {
        $token = wp_get_persistent_token();
        $i     = wp_nonce_tick();

        return substr( wp_hash( $i . '|' . $action . '|' . $token, 'nonce' ), -12, 10 );
    }
endif;
