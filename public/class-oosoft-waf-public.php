<?php
/**
 * Front-end integration for OOSOFT WAF Security.
 *
 * Sends security-hardening HTTP headers on every front-end response.
 *
 * @package OOSOFT_WAF_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Handles public-facing security enhancements (security headers).
 */
class OOSOFT_WAF_Public {

	/**
	 * Registers front-end hooks.
	 */
	public function __construct() {
		add_action( 'send_headers', array( $this, 'send_security_headers' ) );
	}

	/**
	 * Emits security-hardening HTTP response headers.
	 *
	 * These headers are advisory to browsers and do not replace server-level
	 * configuration but provide a meaningful defence-in-depth layer for
	 * sites that cannot modify the server config directly.
	 */
	public function send_security_headers() {
		if ( headers_sent() ) {
			return;
		}

		header( 'X-Content-Type-Options: nosniff' );
		header( 'X-Frame-Options: SAMEORIGIN' );
		header( 'X-XSS-Protection: 1; mode=block' );
		header( 'Referrer-Policy: strict-origin-when-cross-origin' );
		header( 'Permissions-Policy: geolocation=(), microphone=(), camera=()' );
	}
}
