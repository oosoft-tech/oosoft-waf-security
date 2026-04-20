<?php
/**
 * Admin UI for OOSOFT WAF Security.
 *
 * Registers the admin menu, settings pages, and AJAX handlers.
 *
 * @package OOSOFT_WAF_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Handles all WordPress admin integration for the WAF plugin.
 */
class OOSOFT_WAF_Admin {

	/**
	 * Registers hooks on construction.
	 */
	public function __construct() {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'wp_ajax_oosoft_waf_clear_logs', array( $this, 'ajax_clear_logs' ) );
	}

	/**
	 * Registers the top-level admin menu and sub-menus.
	 */
	public function register_menu() {
		add_menu_page(
			__( 'OOSOFT WAF Security', 'oosoft-waf-security' ),
			__( 'WAF Security', 'oosoft-waf-security' ),
			'manage_options',
			'oosoft-waf-security',
			array( $this, 'render_dashboard' ),
			'dashicons-shield',
			80
		);

		add_submenu_page(
			'oosoft-waf-security',
			__( 'Dashboard', 'oosoft-waf-security' ),
			__( 'Dashboard', 'oosoft-waf-security' ),
			'manage_options',
			'oosoft-waf-security',
			array( $this, 'render_dashboard' )
		);

		add_submenu_page(
			'oosoft-waf-security',
			__( 'Settings', 'oosoft-waf-security' ),
			__( 'Settings', 'oosoft-waf-security' ),
			'manage_options',
			'oosoft-waf-settings',
			array( $this, 'render_settings' )
		);

		add_submenu_page(
			'oosoft-waf-security',
			__( 'Security Logs', 'oosoft-waf-security' ),
			__( 'Security Logs', 'oosoft-waf-security' ),
			'manage_options',
			'oosoft-waf-logs',
			array( $this, 'render_logs' )
		);
	}

	/**
	 * Registers all plugin settings with the WordPress Settings API.
	 */
	public function register_settings() {

		// ── Firewall section ────────────────────────────────────────────────
		add_settings_section(
			'oosoft_waf_firewall_section',
			__( 'Request Firewall', 'oosoft-waf-security' ),
			array( $this, 'render_firewall_section_desc' ),
			'oosoft-waf-settings'
		);

		$firewall_fields = array(
			'oosoft_waf_enable_firewall'          => __( 'Enable Request Firewall', 'oosoft-waf-security' ),
			'oosoft_waf_enable_sql_protection'    => __( 'SQL Injection Protection', 'oosoft-waf-security' ),
			'oosoft_waf_enable_xss_protection'    => __( 'XSS Protection', 'oosoft-waf-security' ),
			'oosoft_waf_enable_bad_agents'        => __( 'Block Malicious User Agents', 'oosoft-waf-security' ),
			'oosoft_waf_enable_xmlrpc_protection' => __( 'Block XML-RPC', 'oosoft-waf-security' ),
		);

		foreach ( $firewall_fields as $option => $label ) {
			register_setting(
				'oosoft_waf_settings_group',
				$option,
				array(
					'type'              => 'string',
					'sanitize_callback' => array( $this, 'sanitize_checkbox' ),
					'default'           => '0',
				)
			);
			add_settings_field(
				$option,
				$label,
				array( $this, 'render_checkbox_field' ),
				'oosoft-waf-settings',
				'oosoft_waf_firewall_section',
				array( 'option' => $option )
			);
		}

		// ── Rate limiting section ───────────────────────────────────────────
		add_settings_section(
			'oosoft_waf_rate_section',
			__( 'Brute-Force Rate Limiting', 'oosoft-waf-security' ),
			'__return_false',
			'oosoft-waf-settings'
		);

		register_setting(
			'oosoft_waf_settings_group',
			'oosoft_waf_enable_rate_limiting',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_checkbox' ),
				'default'           => '1',
			)
		);
		add_settings_field(
			'oosoft_waf_enable_rate_limiting',
			__( 'Enable Rate Limiting', 'oosoft-waf-security' ),
			array( $this, 'render_checkbox_field' ),
			'oosoft-waf-settings',
			'oosoft_waf_rate_section',
			array( 'option' => 'oosoft_waf_enable_rate_limiting' )
		);

		register_setting(
			'oosoft_waf_settings_group',
			'oosoft_waf_rate_limit_attempts',
			array(
				'type'              => 'integer',
				'sanitize_callback' => 'absint',
				'default'           => 5,
			)
		);
		add_settings_field(
			'oosoft_waf_rate_limit_attempts',
			__( 'Max Login Attempts', 'oosoft-waf-security' ),
			array( $this, 'render_number_field' ),
			'oosoft-waf-settings',
			'oosoft_waf_rate_section',
			array(
				'option' => 'oosoft_waf_rate_limit_attempts',
				'min'    => 1,
				'max'    => 50,
				/* translators: Unit label appended after number input. */
				'after'  => __( 'attempts before blocking', 'oosoft-waf-security' ),
			)
		);

		register_setting(
			'oosoft_waf_settings_group',
			'oosoft_waf_rate_limit_window',
			array(
				'type'              => 'integer',
				'sanitize_callback' => 'absint',
				'default'           => 5,
			)
		);
		add_settings_field(
			'oosoft_waf_rate_limit_window',
			__( 'Rate-Limit Window', 'oosoft-waf-security' ),
			array( $this, 'render_number_field' ),
			'oosoft-waf-settings',
			'oosoft_waf_rate_section',
			array(
				'option' => 'oosoft_waf_rate_limit_window',
				'min'    => 1,
				'max'    => 60,
				/* translators: Unit label appended after number input. */
				'after'  => __( 'minutes', 'oosoft-waf-security' ),
			)
		);

		// ── Upload scanner section ──────────────────────────────────────────
		add_settings_section(
			'oosoft_waf_upload_section',
			__( 'Upload Malware Scanner', 'oosoft-waf-security' ),
			'__return_false',
			'oosoft-waf-settings'
		);

		register_setting(
			'oosoft_waf_settings_group',
			'oosoft_waf_enable_upload_scanner',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_checkbox' ),
				'default'           => '1',
			)
		);
		add_settings_field(
			'oosoft_waf_enable_upload_scanner',
			__( 'Enable Upload Scanner', 'oosoft-waf-security' ),
			array( $this, 'render_checkbox_field' ),
			'oosoft-waf-settings',
			'oosoft_waf_upload_section',
			array( 'option' => 'oosoft_waf_enable_upload_scanner' )
		);

		// ── Logging section ─────────────────────────────────────────────────
		add_settings_section(
			'oosoft_waf_logging_section',
			__( 'Security Logging', 'oosoft-waf-security' ),
			'__return_false',
			'oosoft-waf-settings'
		);

		register_setting(
			'oosoft_waf_settings_group',
			'oosoft_waf_enable_logging',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_checkbox' ),
				'default'           => '1',
			)
		);
		add_settings_field(
			'oosoft_waf_enable_logging',
			__( 'Enable Security Logging', 'oosoft-waf-security' ),
			array( $this, 'render_checkbox_field' ),
			'oosoft-waf-settings',
			'oosoft_waf_logging_section',
			array( 'option' => 'oosoft_waf_enable_logging' )
		);

		register_setting(
			'oosoft_waf_settings_group',
			'oosoft_waf_log_retention_days',
			array(
				'type'              => 'integer',
				'sanitize_callback' => 'absint',
				'default'           => 30,
			)
		);
		add_settings_field(
			'oosoft_waf_log_retention_days',
			__( 'Log Retention', 'oosoft-waf-security' ),
			array( $this, 'render_number_field' ),
			'oosoft-waf-settings',
			'oosoft_waf_logging_section',
			array(
				'option' => 'oosoft_waf_log_retention_days',
				'min'    => 1,
				'max'    => 365,
				/* translators: Unit label appended after number input. */
				'after'  => __( 'days', 'oosoft-waf-security' ),
			)
		);
	}

	// ── Settings field renderers ────────────────────────────────────────────

	/**
	 * Renders the description for the firewall settings section.
	 */
	public function render_firewall_section_desc() {
		echo '<p>' . esc_html__( 'Configure the request firewall rules applied to every incoming HTTP request.', 'oosoft-waf-security' ) . '</p>';
	}

	/**
	 * Renders a checkbox settings field.
	 *
	 * @param array $args Field arguments: option.
	 */
	public function render_checkbox_field( array $args ) {
		$option = isset( $args['option'] ) ? sanitize_key( $args['option'] ) : '';
		$value  = get_option( $option, '0' );
		?>
		<input type="checkbox"
			id="<?php echo esc_attr( $option ); ?>"
			name="<?php echo esc_attr( $option ); ?>"
			value="1"
			<?php checked( '1', $value ); ?> />
		<?php
	}

	/**
	 * Renders a number settings field with optional trailing label.
	 *
	 * @param array $args Field arguments: option, min, max, after.
	 */
	public function render_number_field( array $args ) {
		$option = isset( $args['option'] ) ? sanitize_key( $args['option'] ) : '';
		$min    = isset( $args['min'] ) ? absint( $args['min'] ) : 1;
		$max    = isset( $args['max'] ) ? absint( $args['max'] ) : 9999;
		$after  = isset( $args['after'] ) ? $args['after'] : '';
		$value  = absint( get_option( $option, 0 ) );
		?>
		<input type="number"
			id="<?php echo esc_attr( $option ); ?>"
			name="<?php echo esc_attr( $option ); ?>"
			value="<?php echo esc_attr( $value ); ?>"
			min="<?php echo esc_attr( $min ); ?>"
			max="<?php echo esc_attr( $max ); ?>"
			class="small-text" />
		<?php if ( '' !== $after ) : ?>
			<span class="description"><?php echo esc_html( $after ); ?></span>
		<?php endif; ?>
		<?php
	}

	/**
	 * Sanitise a checkbox value to '1' or '0'.
	 *
	 * @param mixed $value Raw value from $_POST.
	 * @return string
	 */
	public function sanitize_checkbox( $value ) {
		return ( '1' === (string) $value ) ? '1' : '0';
	}

	// ── Page renderers ──────────────────────────────────────────────────────

	/**
	 * Enqueues admin CSS and JS only on this plugin's pages.
	 *
	 * @param string $hook_suffix Current admin page hook suffix.
	 */
	public function enqueue_assets( $hook_suffix ) {
		$pages = array(
			'toplevel_page_oosoft-waf-security',
			'waf-security_page_oosoft-waf-settings',
			'waf-security_page_oosoft-waf-logs',
		);

		if ( ! in_array( $hook_suffix, $pages, true ) ) {
			return;
		}

		wp_enqueue_style(
			'oosoft-waf-admin',
			OOSOFT_WAF_PLUGIN_URL . 'admin/css/admin-style.css',
			array(),
			OOSOFT_WAF_VERSION
		);

		wp_enqueue_script(
			'oosoft-waf-admin',
			OOSOFT_WAF_PLUGIN_URL . 'admin/js/admin-script.js',
			array( 'jquery' ),
			OOSOFT_WAF_VERSION,
			true
		);

		wp_localize_script(
			'oosoft-waf-admin',
			'oosoftWaf',
			array(
				'ajaxUrl'      => admin_url( 'admin-ajax.php' ),
				'nonce'        => wp_create_nonce( 'oosoft_waf_clear_logs' ),
				'confirmClear' => __( 'Are you sure you want to delete all security logs? This cannot be undone.', 'oosoft-waf-security' ),
				'cleared'      => __( 'All logs have been deleted.', 'oosoft-waf-security' ),
				'error'        => __( 'An error occurred. Please try again.', 'oosoft-waf-security' ),
			)
		);
	}

	/**
	 * Renders the dashboard overview page.
	 */
	public function render_dashboard() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'oosoft-waf-security' ) );
		}

		$stats  = OOSOFT_Logger::get_stats();
		$logs   = OOSOFT_Logger::get_logs( 10, 0 );

		$fw_on     = get_option( 'oosoft_waf_enable_firewall', '1' );
		$scan_on   = get_option( 'oosoft_waf_enable_upload_scanner', '1' );
		$log_on    = get_option( 'oosoft_waf_enable_logging', '1' );
		?>
		<div class="wrap oosoft-waf-wrap">
			<h1><?php esc_html_e( 'OOSOFT WAF Security', 'oosoft-waf-security' ); ?></h1>

			<div class="oosoft-waf-status-bar">
				<?php $this->render_status_pill( __( 'Firewall', 'oosoft-waf-security' ), $fw_on ); ?>
				<?php $this->render_status_pill( __( 'Upload Scanner', 'oosoft-waf-security' ), $scan_on ); ?>
				<?php $this->render_status_pill( __( 'Logging', 'oosoft-waf-security' ), $log_on ); ?>
			</div>

			<h2><?php esc_html_e( 'Attack Statistics', 'oosoft-waf-security' ); ?></h2>
			<div class="oosoft-waf-stats">
				<?php $this->render_stat_card( __( 'Today', 'oosoft-waf-security' ), $stats['today'] ); ?>
				<?php $this->render_stat_card( __( 'Last 7 Days', 'oosoft-waf-security' ), $stats['week'] ); ?>
				<?php $this->render_stat_card( __( 'All Time', 'oosoft-waf-security' ), $stats['total'] ); ?>
			</div>

			<h2><?php esc_html_e( 'Recent Security Events', 'oosoft-waf-security' ); ?></h2>
			<?php if ( empty( $logs ) ) : ?>
				<p><?php esc_html_e( 'No security events recorded yet.', 'oosoft-waf-security' ); ?></p>
			<?php else : ?>
				<?php $this->render_logs_table( $logs ); ?>
				<p>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=oosoft-waf-logs' ) ); ?>">
						<?php esc_html_e( 'View all logs &rarr;', 'oosoft-waf-security' ); ?>
					</a>
				</p>
			<?php endif; ?>

			<div class="oosoft-waf-pro-notice">
				<h2><?php esc_html_e( 'Upgrade to Pro', 'oosoft-waf-security' ); ?></h2>
				<p>
					<?php esc_html_e( 'Unlock Imunify360 integration, automatic quarantine, temporary IP bans, and custom malware signatures.', 'oosoft-waf-security' ); ?>
					<a href="<?php echo esc_url( 'https://oosoft.co.in' ); ?>" target="_blank" rel="noopener noreferrer">
						<?php esc_html_e( 'Learn more at oosoft.co.in', 'oosoft-waf-security' ); ?>
					</a>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Renders the settings form page.
	 */
	public function render_settings() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'oosoft-waf-security' ) );
		}
		?>
		<div class="wrap oosoft-waf-wrap">
			<h1><?php esc_html_e( 'WAF Security Settings', 'oosoft-waf-security' ); ?></h1>

			<form method="post" action="options.php">
				<?php
				settings_fields( 'oosoft_waf_settings_group' );
				do_settings_sections( 'oosoft-waf-settings' );
				submit_button( __( 'Save Settings', 'oosoft-waf-security' ) );
				?>
			</form>

			<hr />
			<h2><?php esc_html_e( 'Pro Features', 'oosoft-waf-security' ); ?></h2>
			<div class="oosoft-pro-section">
				<p>
					<span class="oosoft-pro-badge"><?php esc_html_e( 'PRO', 'oosoft-waf-security' ); ?></span>
					<?php esc_html_e( 'Imunify360 Integration &mdash; advanced cloud malware scanning.', 'oosoft-waf-security' ); ?>
				</p>
				<p>
					<span class="oosoft-pro-badge"><?php esc_html_e( 'PRO', 'oosoft-waf-security' ); ?></span>
					<?php esc_html_e( 'Quarantine Mode &mdash; isolate suspicious uploads instead of deleting them.', 'oosoft-waf-security' ); ?>
				</p>
				<p>
					<span class="oosoft-pro-badge"><?php esc_html_e( 'PRO', 'oosoft-waf-security' ); ?></span>
					<?php esc_html_e( 'Temporary IP Bans &mdash; automatically block attacker IPs for a configurable period.', 'oosoft-waf-security' ); ?>
				</p>
				<p>
					<span class="oosoft-pro-badge"><?php esc_html_e( 'PRO', 'oosoft-waf-security' ); ?></span>
					<?php esc_html_e( 'Custom Malware Signatures &mdash; define your own detection patterns.', 'oosoft-waf-security' ); ?>
				</p>
				<p>
					<a href="<?php echo esc_url( 'https://oosoft.co.in' ); ?>" class="button button-primary" target="_blank" rel="noopener noreferrer">
						<?php esc_html_e( 'Get OOSOFT WAF Pro', 'oosoft-waf-security' ); ?>
					</a>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Renders the full security logs page with pagination.
	 */
	public function render_logs() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'oosoft-waf-security' ) );
		}

		$per_page    = 50;
		$current_page = isset( $_GET['paged'] ) ? absint( $_GET['paged'] ) : 1; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$offset       = ( $current_page - 1 ) * $per_page;
		$total        = OOSOFT_Logger::get_log_count();
		$logs         = OOSOFT_Logger::get_logs( $per_page, $offset );
		$total_pages  = (int) ceil( $total / $per_page );
		?>
		<div class="wrap oosoft-waf-wrap">
			<h1><?php esc_html_e( 'Security Logs', 'oosoft-waf-security' ); ?></h1>

			<p>
				<button type="button" id="oosoft-clear-logs" class="button button-secondary">
					<?php esc_html_e( 'Clear All Logs', 'oosoft-waf-security' ); ?>
				</button>
				<span id="oosoft-clear-result" style="margin-left:10px;"></span>
			</p>

			<?php if ( empty( $logs ) ) : ?>
				<p><?php esc_html_e( 'No security events recorded yet.', 'oosoft-waf-security' ); ?></p>
			<?php else : ?>
				<p>
					<?php
					echo esc_html(
						sprintf(
							/* translators: 1: First row number. 2: Last row number. 3: Total row count. */
							__( 'Showing %1$d&ndash;%2$d of %3$d events.', 'oosoft-waf-security' ),
							$offset + 1,
							min( $offset + $per_page, $total ),
							$total
						)
					);
					?>
				</p>
				<?php $this->render_logs_table( $logs ); ?>
				<?php $this->render_pagination( $current_page, $total_pages ); ?>
			<?php endif; ?>
		</div>
		<?php
	}

	// ── AJAX handlers ───────────────────────────────────────────────────────

	/**
	 * AJAX handler: clears all log entries.
	 */
	public function ajax_clear_logs() {
		check_ajax_referer( 'oosoft_waf_clear_logs', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'oosoft-waf-security' ) ) );
		}

		OOSOFT_Logger::clear_all_logs();

		wp_send_json_success( array( 'message' => __( 'All logs have been deleted.', 'oosoft-waf-security' ) ) );
	}

	// ── Private render helpers ──────────────────────────────────────────────

	/**
	 * Renders a coloured on/off pill badge.
	 *
	 * @param string $label Module label.
	 * @param string $value '1' = active.
	 */
	private function render_status_pill( $label, $value ) {
		$active = ( '1' === (string) $value );
		$class  = $active ? 'oosoft-pill-on' : 'oosoft-pill-off';
		$status = $active ? __( 'ON', 'oosoft-waf-security' ) : __( 'OFF', 'oosoft-waf-security' );
		printf(
			'<span class="oosoft-pill %s"><strong>%s</strong> %s</span> ',
			esc_attr( $class ),
			esc_html( $label ),
			esc_html( $status )
		);
	}

	/**
	 * Renders a stat card with a large number and a label below.
	 *
	 * @param string $label Display label.
	 * @param int    $count Numeric value to display.
	 */
	private function render_stat_card( $label, $count ) {
		?>
		<div class="oosoft-stat-card">
			<span class="oosoft-stat-number"><?php echo esc_html( number_format_i18n( $count ) ); ?></span>
			<span class="oosoft-stat-label"><?php echo esc_html( $label ); ?></span>
		</div>
		<?php
	}

	/**
	 * Renders an HTML table of log rows.
	 *
	 * @param array $logs Array of stdClass log rows from OOSOFT_Logger::get_logs().
	 */
	private function render_logs_table( array $logs ) {
		?>
		<table class="wp-list-table widefat fixed striped oosoft-logs-table">
			<thead>
				<tr>
					<th scope="col" style="width:140px;"><?php esc_html_e( 'Date / Time', 'oosoft-waf-security' ); ?></th>
					<th scope="col" style="width:80px;"><?php esc_html_e( 'Type', 'oosoft-waf-security' ); ?></th>
					<th scope="col" style="width:130px;"><?php esc_html_e( 'Threat', 'oosoft-waf-security' ); ?></th>
					<th scope="col" style="width:120px;"><?php esc_html_e( 'IP Address', 'oosoft-waf-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Request URI', 'oosoft-waf-security' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Blocked Payload', 'oosoft-waf-security' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $logs as $log ) : ?>
					<tr>
						<td><?php echo esc_html( $log->created_at ); ?></td>
						<td><?php echo esc_html( $log->log_type ); ?></td>
						<td><?php echo esc_html( $log->attack_type ); ?></td>
						<td><code><?php echo esc_html( $log->ip_address ); ?></code></td>
						<td><code><?php echo esc_html( $log->request_uri ); ?></code></td>
						<td>
							<?php if ( ! empty( $log->blocked_value ) ) : ?>
								<code><?php echo esc_html( $log->blocked_value ); ?></code>
							<?php else : ?>
								&mdash;
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}

	/**
	 * Renders previous/next page links for the logs table.
	 *
	 * @param int $current      Current page number (1-based).
	 * @param int $total_pages  Total number of pages.
	 */
	private function render_pagination( $current, $total_pages ) {
		if ( $total_pages <= 1 ) {
			return;
		}

		echo '<div class="tablenav"><div class="tablenav-pages">';

		if ( $current > 1 ) {
			$prev_url = add_query_arg(
				array(
					'page'  => 'oosoft-waf-logs',
					'paged' => $current - 1,
				),
				admin_url( 'admin.php' )
			);
			printf(
				'<a class="prev-page button" href="%s">&laquo; %s</a> ',
				esc_url( $prev_url ),
				esc_html__( 'Previous', 'oosoft-waf-security' )
			);
		}

		printf(
			'<span class="paging-input">%s</span> ',
			esc_html(
				sprintf(
					/* translators: 1: Current page. 2: Total pages. */
					__( 'Page %1$d of %2$d', 'oosoft-waf-security' ),
					$current,
					$total_pages
				)
			)
		);

		if ( $current < $total_pages ) {
			$next_url = add_query_arg(
				array(
					'page'  => 'oosoft-waf-logs',
					'paged' => $current + 1,
				),
				admin_url( 'admin.php' )
			);
			printf(
				'<a class="next-page button" href="%s">%s &raquo;</a>',
				esc_url( $next_url ),
				esc_html__( 'Next', 'oosoft-waf-security' )
			);
		}

		echo '</div></div>';
	}
}
