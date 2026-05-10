<?php
/**
 * Global helper functions for OOSOFT WAF Security.
 *
 * @package OOSOFT_WAF_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Checks whether a Pro feature is unlocked by the current license.
 *
 * In Phase 1 no license system exists; this always returns false.
 * Phase 2 will populate the filtered array via the license manager.
 *
 * @param string $feature Feature identifier (e.g. 'imunify360', 'quarantine').
 * @return bool
 */
function oosoft_license_allows( $feature ) {
	/**
	 * Filters the list of Pro features currently allowed by the license.
	 *
	 * @param string[] $features Allowed feature identifiers.
	 */
	$allowed = apply_filters( 'oosoft_waf_pro_features', array() );
	return in_array( $feature, (array) $allowed, true );
}

/**
 * Returns the real visitor IP address, preferring trusted proxy headers.
 *
 * @return string Validated IP or empty string on failure.
 */
function oosoft_waf_get_client_ip() {
	$remote = isset( $_SERVER['REMOTE_ADDR'] )
		? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
		: '';

	/**
	 * Filters the list of trusted proxy IP addresses.
	 *
	 * Proxy headers (CF-Connecting-IP, X-Forwarded-For) are only honoured
	 * when REMOTE_ADDR matches an IP in this list. Leave empty (default) to
	 * always use REMOTE_ADDR directly.
	 *
	 * @param string[] $proxies List of trusted proxy IP addresses.
	 */
	$trusted_proxies = apply_filters( 'oosoft_waf_trusted_proxies', array() );

	if ( ! empty( $trusted_proxies ) && in_array( $remote, (array) $trusted_proxies, true ) ) {
		if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
			$candidate = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
			if ( filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
				return $candidate;
			}
		}

		if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$parts     = explode( ',', sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
			$candidate = trim( $parts[0] );
			if ( filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
				return $candidate;
			}
		}
	}

	return filter_var( $remote, FILTER_VALIDATE_IP ) ? $remote : '';
}

/**
 * Returns the current request URI, sanitised as a raw URL.
 *
 * @return string
 */
function oosoft_waf_get_request_uri() {
	if ( ! empty( $_SERVER['REQUEST_URI'] ) ) {
		return esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) );
	}
	return '';
}

/**
 * Returns the current HTTP user-agent string, sanitised as plain text.
 *
 * @return string
 */
function oosoft_waf_get_user_agent() {
	if ( ! empty( $_SERVER['HTTP_USER_AGENT'] ) ) {
		return sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) );
	}
	return '';
}

/**
 * Returns the current HTTP request method in upper case.
 *
 * @return string e.g. 'GET', 'POST'.
 */
function oosoft_waf_get_request_method() {
	if ( ! empty( $_SERVER['REQUEST_METHOD'] ) ) {
		return strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) );
	}
	return '';
}

/**
 * Sends a 403 response and terminates execution with a user-friendly message.
 *
 * @param string $reason Human-readable reason shown to the visitor (plain text).
 */
function oosoft_waf_block_request( $reason = '' ) {
	$title = __( 'Access Blocked', 'oosoft-waf-security' );
	$body  = $reason
		? $reason
		: __( 'Your request has been blocked by the security firewall.', 'oosoft-waf-security' );

	wp_die(
		esc_html( $body ),
		esc_html( $title ),
		array( 'response' => 403 )
	);
}
