<?php
/**
 * Upload malware scanner for OOSOFT WAF Security.
 *
 * Hooks into WordPress upload pre-filter to inspect every incoming file before
 * it is moved to the uploads directory, blocking known-dangerous extensions,
 * double-extension attacks, and files matching malware signatures.
 *
 * @package OOSOFT_WAF_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Scans uploaded files and blocks threats before they reach the filesystem.
 */
class OOSOFT_Upload_Scanner {

	/**
	 * File extensions that should never be allowed to upload.
	 *
	 * @var string[]
	 */
	private $dangerous_extensions = array(
		'php', 'php3', 'php4', 'php5', 'php6', 'php7', 'php8',
		'phtml', 'pht', 'phar',
		'asp', 'aspx', 'asa', 'asax', 'ascx', 'ashx', 'asmx',
		'exe', 'dll', 'com', 'bat', 'cmd',
		'sh', 'bash', 'csh', 'ksh', 'zsh',
		'cgi', 'pl', 'py', 'rb', 'lua',
		'htaccess', 'htpasswd',
	);

	/**
	 * Plain-text byte sequences found in common PHP web-shell malware.
	 *
	 * Checked against the raw file content (first 50 KB).
	 *
	 * @var string[]
	 */
	private $malware_signatures = array(
		'eval(base64_decode',
		'eval(gzinflate',
		'eval(str_rot13',
		'eval(gzuncompress',
		'eval(gzdecode',
		"preg_replace('/.*/e'",
		'preg_replace("/.*/e"',
		'assert($_',
		'assert($_POST',
		'assert($_GET',
		'system($_REQUEST',
		'passthru($_REQUEST',
		'exec($_REQUEST',
		'shell_exec($_REQUEST',
		'FilesMan',
		'c99shell',
		'r57shell',
		'phpspy',
		'b374k',
		'weevely',
		'<?php eval',
		'base64_decode(str_rot13(',
		'gzinflate(base64_decode(',
		'str_rot13(gzinflate(',
	);

	/**
	 * Scans a file from the WordPress upload pre-filter hook.
	 *
	 * Returns the $file array unmodified on success, or with 'error' set to a
	 * translated string if the upload should be rejected.
	 *
	 * @param array $file Associative array with keys: name, tmp_name, error, size, type.
	 * @return array
	 */
	public function scan( array $file ) {
		if ( ! empty( $file['error'] ) ) {
			return $file;
		}

		$result = $this->check_extension( $file );
		if ( ! empty( $result['error'] ) ) {
			return $result;
		}

		$result = $this->check_double_extension( $file );
		if ( ! empty( $result['error'] ) ) {
			return $result;
		}

		$result = $this->check_malware_signatures( $file );
		if ( ! empty( $result['error'] ) ) {
			return $result;
		}

		// Pro: Imunify360 scanning.
		if ( oosoft_license_allows( 'imunify360' ) ) {
			$result = $this->scan_with_imunify360( $file );
			if ( ! empty( $result['error'] ) ) {
				return $result;
			}
		}

		// Pro: quarantine instead of outright rejection.
		if ( oosoft_license_allows( 'quarantine' ) ) {
			// Architecture hook: quarantine logic loaded by Pro module.
			$file = apply_filters( 'oosoft_waf_quarantine_file', $file );
		}

		return $file;
	}

	/**
	 * Blocks files whose final extension is on the dangerous list.
	 *
	 * @param array $file Upload file array.
	 * @return array
	 */
	private function check_extension( array $file ) {
		$name      = isset( $file['name'] ) ? sanitize_file_name( $file['name'] ) : '';
		$ext       = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );

		if ( in_array( $ext, $this->dangerous_extensions, true ) ) {
			OOSOFT_Logger::log( 'upload', 'dangerous_extension', $name );
			$this->notify_admin( $name, 'dangerous_extension' );

			$file['error'] = sprintf(
				/* translators: %s: File extension. */
				__( 'Upload blocked: the file extension ".%s" is not permitted for security reasons.', 'oosoft-waf-security' ),
				esc_html( $ext )
			);
		}

		return $file;
	}

	/**
	 * Blocks files that carry a dangerous extension hidden under a second extension,
	 * e.g. shell.php.jpg or shell.jpg.php.
	 *
	 * @param array $file Upload file array.
	 * @return array
	 */
	private function check_double_extension( array $file ) {
		$name  = isset( $file['name'] ) ? sanitize_file_name( $file['name'] ) : '';
		$parts = explode( '.', $name );

		if ( count( $parts ) < 3 ) {
			return $file;
		}

		// Check every segment except the first (filename) for dangerous extensions.
		array_shift( $parts );
		foreach ( $parts as $part ) {
			if ( in_array( strtolower( $part ), $this->dangerous_extensions, true ) ) {
				OOSOFT_Logger::log( 'upload', 'double_extension', $name );
				$this->notify_admin( $name, 'double_extension' );

				$file['error'] = __( 'Upload blocked: double-extension attack detected.', 'oosoft-waf-security' );
				return $file;
			}
		}

		return $file;
	}

	/**
	 * Reads up to 50 KB of the temporary file and matches known malware byte-strings.
	 *
	 * Uses WP_Filesystem for Plugin Check compliance.
	 *
	 * @param array $file Upload file array.
	 * @return array
	 */
	private function check_malware_signatures( array $file ) {
		$tmp = isset( $file['tmp_name'] ) ? $file['tmp_name'] : '';
		if ( '' === $tmp ) {
			return $file;
		}

		$content = $this->read_file_head( $tmp, 51200 );
		if ( '' === $content ) {
			return $file;
		}

		foreach ( $this->malware_signatures as $sig ) {
			if ( false !== strpos( $content, $sig ) ) {
				$name = isset( $file['name'] ) ? sanitize_file_name( $file['name'] ) : '';
				OOSOFT_Logger::log( 'upload', 'malware_signature', $name . ' [sig:' . $sig . ']' );
				$this->notify_admin( $name, 'malware_signature' );

				$file['error'] = __( 'Upload blocked: the file contains a known malware signature.', 'oosoft-waf-security' );
				return $file;
			}
		}

		return $file;
	}

	/**
	 * Reads the first $bytes bytes from $path using WP_Filesystem.
	 *
	 * Falls back to an empty string if the filesystem cannot be initialised.
	 *
	 * @param string $path  Absolute path to the temporary upload file.
	 * @param int    $bytes Maximum bytes to read.
	 * @return string
	 */
	private function read_file_head( $path, $bytes = 51200 ) {
		global $wp_filesystem;

		if ( empty( $wp_filesystem ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
			WP_Filesystem();
		}

		if ( ! ( $wp_filesystem instanceof WP_Filesystem_Base ) ) {
			return '';
		}

		$content = $wp_filesystem->get_contents( $path );

		if ( false === $content ) {
			return '';
		}

		return substr( $content, 0, $bytes );
	}

	/**
	 * Sends an admin email when a malicious upload is blocked.
	 *
	 * @param string $filename  Sanitised filename.
	 * @param string $reason    Threat type identifier.
	 */
	private function notify_admin( $filename, $reason ) {
		$admin_email = get_option( 'admin_email' );
		if ( ! is_email( $admin_email ) ) {
			return;
		}

		$site    = get_bloginfo( 'name' );
		$subject = sprintf(
			/* translators: %s: Site name. */
			__( '[%s] Malicious Upload Blocked', 'oosoft-waf-security' ),
			$site
		);

		$reason_label = sanitize_text_field( $reason );
		$body         = sprintf(
			/* translators: 1: Filename. 2: Reason. 3: IP address. */
			__( "OOSOFT WAF Security blocked a malicious upload attempt.\n\nFile: %1\$s\nReason: %2\$s\nIP: %3\$s\n\nPlease review your security logs.", 'oosoft-waf-security' ),
			$filename,
			$reason_label,
			oosoft_waf_get_client_ip()
		);

		wp_mail( sanitize_email( $admin_email ), $subject, $body );
	}

	/**
	 * Pro stub: Imunify360 scan integration.
	 *
	 * This method is a no-op in Phase 1. The Pro licence module will
	 * override it via the oosoft_waf_pro_features filter.
	 *
	 * @param array $file Upload file array.
	 * @return array
	 */
	private function scan_with_imunify360( array $file ) {
		return apply_filters( 'oosoft_waf_imunify360_scan', $file );
	}
}
