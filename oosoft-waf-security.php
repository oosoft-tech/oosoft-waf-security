<?php
/**
 * Plugin Name:       OOSOFT WAF Security
 * Plugin URI:        https://oosoft.co.in
 * Description:       A production-ready WordPress application-level Web Application Firewall with request filtering, upload malware protection, and security logging.
 * Version:           1.0.0
 * Requires at least: 5.9
 * Requires PHP:      7.4
 * Author:            OOSOFT Technology
 * Author URI:        https://oosoft.co.in
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       oosoft-waf-security
 * Domain Path:       /languages
 *
 * @package OOSOFT_WAF_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'OOSOFT_WAF_VERSION', '1.0.0' );
define( 'OOSOFT_WAF_PLUGIN_FILE', __FILE__ );
define( 'OOSOFT_WAF_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'OOSOFT_WAF_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

require_once OOSOFT_WAF_PLUGIN_DIR . 'includes/functions.php';
require_once OOSOFT_WAF_PLUGIN_DIR . 'includes/class-oosoft-logger.php';
require_once OOSOFT_WAF_PLUGIN_DIR . 'includes/class-oosoft-rules-engine.php';
require_once OOSOFT_WAF_PLUGIN_DIR . 'includes/class-oosoft-upload-scanner.php';
require_once OOSOFT_WAF_PLUGIN_DIR . 'includes/class-oosoft-waf-core.php';

if ( is_admin() ) {
	require_once OOSOFT_WAF_PLUGIN_DIR . 'admin/class-oosoft-waf-admin.php';
}

require_once OOSOFT_WAF_PLUGIN_DIR . 'public/class-oosoft-waf-public.php';

register_activation_hook( __FILE__, 'oosoft_waf_activate' );
register_deactivation_hook( __FILE__, 'oosoft_waf_deactivate' );

/**
 * Handles plugin activation tasks.
 */
function oosoft_waf_activate() {
	OOSOFT_Logger::create_table();
	oosoft_waf_set_default_options();

	if ( ! wp_next_scheduled( 'oosoft_waf_daily_cleanup' ) ) {
		wp_schedule_event( time(), 'daily', 'oosoft_waf_daily_cleanup' );
	}

	flush_rewrite_rules();
}

/**
 * Handles plugin deactivation tasks.
 */
function oosoft_waf_deactivate() {
	wp_clear_scheduled_hook( 'oosoft_waf_daily_cleanup' );
	flush_rewrite_rules();
}

/**
 * Sets default plugin options on first activation.
 */
function oosoft_waf_set_default_options() {
	$defaults = array(
		'oosoft_waf_enable_firewall'          => '1',
		'oosoft_waf_enable_sql_protection'    => '1',
		'oosoft_waf_enable_xss_protection'    => '1',
		'oosoft_waf_enable_bad_agents'        => '1',
		'oosoft_waf_enable_xmlrpc_protection' => '0',
		'oosoft_waf_enable_rate_limiting'     => '1',
		'oosoft_waf_rate_limit_attempts'      => '5',
		'oosoft_waf_rate_limit_window'        => '5',
		'oosoft_waf_enable_upload_scanner'    => '1',
		'oosoft_waf_enable_logging'           => '1',
		'oosoft_waf_log_retention_days'       => '30',
	);

	foreach ( $defaults as $key => $value ) {
		if ( false === get_option( $key ) ) {
			update_option( $key, $value );
		}
	}
}

/**
 * Loads the plugin text domain and initialises all modules.
 */
function oosoft_waf_init() {
	load_plugin_textdomain(
		'oosoft-waf-security',
		false,
		dirname( plugin_basename( OOSOFT_WAF_PLUGIN_FILE ) ) . '/languages'
	);

	OOSOFT_WAF_Core::get_instance();

	if ( is_admin() ) {
		new OOSOFT_WAF_Admin();
	}

	new OOSOFT_WAF_Public();
}
add_action( 'plugins_loaded', 'oosoft_waf_init' );

add_action( 'oosoft_waf_daily_cleanup', array( 'OOSOFT_Logger', 'purge_old_logs' ) );
