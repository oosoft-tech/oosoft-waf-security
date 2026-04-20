<?php
/**
 * Security event logger for OOSOFT WAF Security.
 *
 * @package OOSOFT_WAF_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Writes and queries WAF security log entries stored in a custom DB table.
 */
class OOSOFT_Logger {

	/**
	 * Unprefixed table name.
	 */
	const TABLE = 'oosoft_waf_logs';

	/**
	 * Creates the log table using dbDelta.
	 */
	public static function create_table() {
		global $wpdb;

		$table   = $wpdb->prefix . self::TABLE;
		$charset = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table} (
			id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			log_type varchar(50) NOT NULL DEFAULT '',
			ip_address varchar(45) NOT NULL DEFAULT '',
			request_uri text NOT NULL,
			user_agent text,
			attack_type varchar(100) NOT NULL DEFAULT '',
			blocked_value text,
			created_at datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
			PRIMARY KEY  (id),
			KEY log_type (log_type),
			KEY ip_address (ip_address),
			KEY created_at (created_at)
		) {$charset};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	/**
	 * Writes a single log entry.
	 *
	 * @param string $log_type     Category: 'attack' or 'upload'.
	 * @param string $attack_type  Specific threat type, e.g. 'sql_injection'.
	 * @param string $blocked_value Truncated payload that triggered the block.
	 */
	public static function log( $log_type, $attack_type = '', $blocked_value = '' ) {
		if ( ! get_option( 'oosoft_waf_enable_logging', '1' ) ) {
			return;
		}

		global $wpdb;

		$wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$wpdb->prefix . self::TABLE,
			array(
				'log_type'      => sanitize_text_field( $log_type ),
				'ip_address'    => oosoft_waf_get_client_ip(),
				'request_uri'   => oosoft_waf_get_request_uri(),
				'user_agent'    => oosoft_waf_get_user_agent(),
				'attack_type'   => sanitize_text_field( $attack_type ),
				'blocked_value' => sanitize_textarea_field( substr( $blocked_value, 0, 500 ) ),
				'created_at'    => current_time( 'mysql' ),
			),
			array( '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * Returns a paginated list of log entries (newest first).
	 *
	 * Results are cached for 60 seconds to reduce DB load on the admin page.
	 *
	 * @param int $limit  Rows per page.
	 * @param int $offset Zero-based row offset.
	 * @return array Array of stdClass rows.
	 */
	public static function get_logs( $limit = 50, $offset = 0 ) {
		global $wpdb;

		$limit  = absint( $limit );
		$offset = absint( $offset );

		$cache_key = 'oosoft_waf_logs_' . $limit . '_' . $offset;
		$cached    = wp_cache_get( $cache_key, 'oosoft_waf' );

		if ( false !== $cached ) {
			return $cached;
		}

		$table = esc_sql( $wpdb->prefix . self::TABLE );

		$results = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT * FROM {$table} ORDER BY created_at DESC LIMIT %d OFFSET %d",
				$limit,
				$offset
			)
		);

		wp_cache_set( $cache_key, $results, 'oosoft_waf', 60 );

		return $results;
	}

	/**
	 * Returns the total number of log rows.
	 *
	 * @return int
	 */
	public static function get_log_count() {
		global $wpdb;

		$cache_key = 'oosoft_waf_log_count';
		$cached    = wp_cache_get( $cache_key, 'oosoft_waf' );

		if ( false !== $cached ) {
			return (int) $cached;
		}

		$table = esc_sql( $wpdb->prefix . self::TABLE );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );

		wp_cache_set( $cache_key, $count, 'oosoft_waf', 60 );

		return $count;
	}

	/**
	 * Returns aggregate attack counts for the dashboard stats cards.
	 *
	 * @return array Keys: today, week, total.
	 */
	public static function get_stats() {
		global $wpdb;

		$cache_key = 'oosoft_waf_stats';
		$cached    = wp_cache_get( $cache_key, 'oosoft_waf' );

		if ( false !== $cached ) {
			return $cached;
		}

		$table = esc_sql( $wpdb->prefix . self::TABLE );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$today = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE DATE(created_at) = CURDATE()" );
		$week  = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)" );
		$total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		$stats = array(
			'today' => $today,
			'week'  => $week,
			'total' => $total,
		);

		wp_cache_set( $cache_key, $stats, 'oosoft_waf', 60 );

		return $stats;
	}

	/**
	 * Deletes log rows older than the configured retention period.
	 *
	 * Called by a daily WP-Cron event registered on plugin activation.
	 */
	public static function purge_old_logs() {
		$days = absint( get_option( 'oosoft_waf_log_retention_days', 30 ) );
		if ( $days < 1 ) {
			return;
		}

		global $wpdb;

		$table = esc_sql( $wpdb->prefix . self::TABLE );

		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"DELETE FROM {$table} WHERE created_at < DATE_SUB(NOW(), INTERVAL %d DAY)",
				$days
			)
		);

		wp_cache_delete( 'oosoft_waf_stats', 'oosoft_waf' );
		wp_cache_delete( 'oosoft_waf_log_count', 'oosoft_waf' );
	}

	/**
	 * Truncates the entire log table (used by the admin clear-logs action).
	 */
	public static function clear_all_logs() {
		global $wpdb;

		$table = esc_sql( $wpdb->prefix . self::TABLE );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( "TRUNCATE TABLE {$table}" );

		wp_cache_delete( 'oosoft_waf_stats', 'oosoft_waf' );
		wp_cache_delete( 'oosoft_waf_log_count', 'oosoft_waf' );
	}
}
