<?php
/**
 * Core orchestrator for OOSOFT WAF Security.
 *
 * Bootstraps all protection modules and registers WordPress hooks.
 *
 * @package OOSOFT_WAF_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Singleton that wires the Rules Engine and Upload Scanner into WordPress.
 */
class OOSOFT_WAF_Core {

	/**
	 * Singleton instance.
	 *
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * Rules engine instance.
	 *
	 * @var OOSOFT_Rules_Engine
	 */
	private $rules_engine;

	/**
	 * Upload scanner instance.
	 *
	 * @var OOSOFT_Upload_Scanner
	 */
	private $upload_scanner;

	/**
	 * Returns (and lazily creates) the singleton instance.
	 *
	 * @return self
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Private constructor: registers all hooks.
	 */
	private function __construct() {
		$this->rules_engine   = new OOSOFT_Rules_Engine();
		$this->upload_scanner = new OOSOFT_Upload_Scanner();

		$this->register_hooks();
	}

	/**
	 * Wires protection modules into the WordPress hook system.
	 */
	private function register_hooks() {
		// Run request firewall early, before page rendering starts.
		add_action( 'init', array( $this, 'run_request_firewall' ), 1 );

		// Track real failed logins for rate limiting.
		add_action( 'wp_login_failed', array( $this->rules_engine, 'on_login_failed' ) );

		// Inspect uploads before WordPress moves them into the uploads directory.
		add_filter( 'wp_handle_upload_prefilter', array( $this, 'handle_upload' ) );
	}

	/**
	 * Runs the request firewall if enabled.
	 */
	public function run_request_firewall() {
		if ( get_option( 'oosoft_waf_enable_firewall', '1' ) ) {
			$this->rules_engine->check_request();
		}
	}

	/**
	 * Passes an upload through the malware scanner if enabled.
	 *
	 * @param array $file WordPress upload file array.
	 * @return array
	 */
	public function handle_upload( array $file ) {
		if ( get_option( 'oosoft_waf_enable_upload_scanner', '1' ) ) {
			return $this->upload_scanner->scan( $file );
		}
		return $file;
	}
}
