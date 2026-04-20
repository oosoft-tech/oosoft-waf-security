<?php
/**
 * Request firewall rules engine for OOSOFT WAF Security.
 *
 * Inspects incoming HTTP request data for known attack patterns and blocks
 * malicious requests before WordPress processes them further.
 *
 * @package OOSOFT_WAF_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Analyses request data and enforces firewall rules.
 */
class OOSOFT_Rules_Engine {

	/**
	 * Regex patterns that indicate SQL injection attempts.
	 *
	 * @var string[]
	 */
	private $sql_patterns = array(
		'/(\%27)|(\')|(\-\-)|(\%23)|(#)/i',
		'/((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i',
		'/\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/i',
		'/((\%27)|(\'))union/i',
		'/exec(\s|\+)+(s|x)p\w+/i',
		'/UNION[\s\/\*]+SELECT/i',
		'/INSERT[\s\/\*]+INTO/i',
		'/DELETE[\s\/\*]+FROM/i',
		'/DROP[\s\/\*]+TABLE/i',
		'/UPDATE[\s\/\*]+\w+[\s\/\*]+SET/i',
		'/SELECT[\s\/\*]+.*[\s\/\*]+FROM/i',
		'/LOAD[\s\/\*]+DATA/i',
		'/INTO[\s\/\*]+(OUTFILE|DUMPFILE)/i',
		'/BENCHMARK\s*\(/i',
		'/SLEEP\s*\(\s*\d/i',
	);

	/**
	 * Regex patterns that indicate XSS attempts.
	 *
	 * @var string[]
	 */
	private $xss_patterns = array(
		'/<script[\s>]/i',
		'/<\/script>/i',
		'/javascript\s*:/i',
		'/vbscript\s*:/i',
		'/on(?:click|load|error|mouseover|focus|blur|change|submit|reset|keydown|keyup|keypress)\s*=/i',
		'/<\s*iframe[\s>]/i',
		'/<\s*object[\s>]/i',
		'/<\s*embed[\s>]/i',
		'/<\s*link[\s>]/i',
		'/document\s*\.\s*cookie/i',
		'/document\s*\.\s*write\s*\(/i',
		'/window\s*\.\s*location/i',
		'/eval\s*\(/i',
		'/expression\s*\(/i',
		'/&#x?[0-9a-f]+;/i',
		'/data\s*:\s*text\s*\/\s*(html|javascript)/i',
	);

	/**
	 * Substrings found in user-agents of known scanners and exploit tools.
	 *
	 * @var string[]
	 */
	private $bad_agents = array(
		'sqlmap',
		'nikto',
		'nessus',
		'acunetix',
		'burpsuite',
		'w3af',
		'nmap',
		'masscan',
		'zgrab',
		'dirbuster',
		'wfuzz',
		'havij',
		'openvas',
		'metasploit',
		'hydra',
		'medusa',
		'joomscan',
		'wpscan',
		'arachni',
		'skipfish',
	);

	/**
	 * Runs all enabled firewall checks against the current request.
	 */
	public function check_request() {
		if ( get_option( 'oosoft_waf_enable_bad_agents', '1' ) ) {
			$this->check_user_agent();
		}

		if ( get_option( 'oosoft_waf_enable_xmlrpc_protection', '0' ) ) {
			$this->check_xmlrpc();
		}

		if ( get_option( 'oosoft_waf_enable_rate_limiting', '1' ) ) {
			$this->check_rate_limit();
		}

		if ( get_option( 'oosoft_waf_enable_sql_protection', '1' ) || get_option( 'oosoft_waf_enable_xss_protection', '1' ) ) {
			$this->check_request_params();
		}
	}

	/**
	 * Blocks requests from known malicious user-agents.
	 */
	private function check_user_agent() {
		$ua = oosoft_waf_get_user_agent();
		if ( '' === $ua ) {
			return;
		}

		$ua_lower = strtolower( $ua );

		foreach ( $this->bad_agents as $bad ) {
			if ( false !== strpos( $ua_lower, $bad ) ) {
				OOSOFT_Logger::log( 'attack', 'bad_user_agent', $ua );
				oosoft_waf_block_request(
					__( 'Your request has been blocked by the security firewall.', 'oosoft-waf-security' )
				);
			}
		}
	}

	/**
	 * Blocks all requests to the XML-RPC endpoint when protection is enabled.
	 */
	private function check_xmlrpc() {
		$uri = oosoft_waf_get_request_uri();
		if ( false !== strpos( $uri, 'xmlrpc.php' ) ) {
			OOSOFT_Logger::log( 'attack', 'xmlrpc_blocked', $uri );
			oosoft_waf_block_request(
				__( 'XML-RPC access is disabled on this site.', 'oosoft-waf-security' )
			);
		}
	}

	/**
	 * Enforces brute-force rate limiting on login POST requests.
	 *
	 * Tracks failed login counts via transients, keyed by IP address.
	 */
	private function check_rate_limit() {
		$uri = oosoft_waf_get_request_uri();

		if ( false === strpos( $uri, 'wp-login.php' ) ) {
			return;
		}

		if ( 'POST' !== oosoft_waf_get_request_method() ) {
			return;
		}

		$ip          = oosoft_waf_get_client_ip();
		$transient   = 'oosoft_waf_rl_' . md5( $ip );
		$attempts    = (int) get_transient( $transient );
		$max         = absint( get_option( 'oosoft_waf_rate_limit_attempts', 5 ) );
		$window_mins = absint( get_option( 'oosoft_waf_rate_limit_window', 5 ) );
		$window_secs = $window_mins * MINUTE_IN_SECONDS;

		if ( $attempts >= $max ) {
			OOSOFT_Logger::log( 'attack', 'brute_force', $ip );
			status_header( 429 );
			oosoft_waf_block_request(
				__( 'Too many login attempts. Please wait a few minutes before trying again.', 'oosoft-waf-security' )
			);
		}

		set_transient( $transient, $attempts + 1, $window_secs );
	}

	/**
	 * Records a failed login attempt against the rate-limit counter.
	 *
	 * Hooked on wp_login_failed so only real authentication failures count.
	 */
	public function on_login_failed() {
		if ( ! get_option( 'oosoft_waf_enable_rate_limiting', '1' ) ) {
			return;
		}

		$ip        = oosoft_waf_get_client_ip();
		$transient = 'oosoft_waf_rl_' . md5( $ip );
		$attempts  = (int) get_transient( $transient );

		$window_mins = absint( get_option( 'oosoft_waf_rate_limit_window', 5 ) );
		set_transient( $transient, $attempts + 1, $window_mins * MINUTE_IN_SECONDS );
	}

	/**
	 * Checks all GET and POST parameters for SQL injection and XSS patterns.
	 *
	 * Raw superglobal values are read intentionally so attack payloads are
	 * visible before sanitisation strips the offending characters.
	 */
	private function check_request_params() {
		$sql_enabled = get_option( 'oosoft_waf_enable_sql_protection', '1' );
		$xss_enabled = get_option( 'oosoft_waf_enable_xss_protection', '1' );

		// phpcs:disable WordPress.Security.NonceVerification.Recommended,WordPress.Security.NonceVerification.Missing
		$sources = array(
			'get'  => $_GET,
			'post' => $_POST,
		);
		// phpcs:enable WordPress.Security.NonceVerification.Recommended,WordPress.Security.NonceVerification.Missing

		foreach ( $sources as $source ) {
			if ( ! is_array( $source ) ) {
				continue;
			}

			foreach ( $source as $value ) {
				// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
				$raw = wp_unslash( (string) $value );

				if ( $sql_enabled && $this->matches_any( $raw, $this->sql_patterns ) ) {
					OOSOFT_Logger::log( 'attack', 'sql_injection', substr( $raw, 0, 200 ) );
					oosoft_waf_block_request(
						__( 'Your request has been blocked by the security firewall.', 'oosoft-waf-security' )
					);
				}

				if ( $xss_enabled && $this->matches_any( $raw, $this->xss_patterns ) ) {
					OOSOFT_Logger::log( 'attack', 'xss', substr( $raw, 0, 200 ) );
					oosoft_waf_block_request(
						__( 'Your request has been blocked by the security firewall.', 'oosoft-waf-security' )
					);
				}
			}
		}
	}

	/**
	 * Tests a string against an array of regex patterns.
	 *
	 * @param string   $value    String to test.
	 * @param string[] $patterns Array of regex patterns.
	 * @return bool True if any pattern matches.
	 */
	private function matches_any( $value, array $patterns ) {
		foreach ( $patterns as $pattern ) {
			if ( preg_match( $pattern, $value ) ) {
				return true;
			}
		}
		return false;
	}
}
