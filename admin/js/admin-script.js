/* global jQuery, oosoftWaf */
( function ( $ ) {
	'use strict';

	$( function () {

		var $btn    = $( '#oosoft-clear-logs' );
		var $result = $( '#oosoft-clear-result' );

		if ( ! $btn.length ) {
			return;
		}

		$btn.on( 'click', function () {
			if ( ! window.confirm( oosoftWaf.confirmClear ) ) {
				return;
			}

			$btn.prop( 'disabled', true );
			$result.text( '' );

			$.post(
				oosoftWaf.ajaxUrl,
				{
					action : 'oosoft_waf_clear_logs',
					nonce  : oosoftWaf.nonce
				},
				function ( response ) {
					if ( response.success ) {
						$result.css( 'color', '#1a6b35' ).text( oosoftWaf.cleared );
						$( '.oosoft-logs-table tbody' ).empty();
					} else {
						$result.css( 'color', '#8b1a1a' ).text( oosoftWaf.error );
					}
				}
			).fail( function () {
				$result.css( 'color', '#8b1a1a' ).text( oosoftWaf.error );
			} ).always( function () {
				$btn.prop( 'disabled', false );
			} );
		} );

	} );

}( jQuery ) );
