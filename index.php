<?php
/*
Plugin Name: Odd Scanner
Plugin URI: http://oddalice.com
Description: This plugin checks all your installed plugins with the <a href="https://wpvulndb.com">WPScan Vulnerability Database</a> for known vulnerabilities.
Version: 0.1
Author: Odd Alice
Author URI: http://oddalice.com
Text Domain: odd-scanner
Domain Path: /languages
*/

class OddScanner {
  private $transient_name = 'ODD-SCANNER';

  function __construct() {
    add_action( 'plugins_loaded', array( $this, 'load_plugin_textdomain' ) );
    add_action( 'admin_menu', array( $this, 'admin_menu' ) );
  }

  function load_plugin_textdomain() {
    load_plugin_textdomain( 'odd-scanner', FALSE, basename( dirname( __FILE__ ) ) . '/languages/' );
  }

  function admin_menu() {
		add_options_page(
			'Odd Scanner',
			'Odd Scanner',
			'manage_options',
			'odd-scanner',
			array(
				$this,
				'settings_page'
			)
		);
	}

	function settings_page() {
    $plugins = $this->scan_plugins();
		?>
    <div class="wrap">
      <h1>Odd Scanner</h1>
      <p><?php _e( 'This plugin checks all your installed plugins with the <a href="https://wpvulndb.com">WPScan Vulnerability Database</a>. It does not contain information about every plugin and the information may be inaccurate.<br /> To be on the safe side you should always be running the latest version of your plugins.', 'odd-scanner' ); ?></p>

      <?php
        foreach ( $plugins as $plugin ) :
          echo '<h2>' . $plugin['Name'] . '</h2>';

          if ( $plugin['wpvulndb'] ) :
            $wpvulndb = array_values($plugin['wpvulndb'])[0];
            $vulnerabilities = $wpvulndb['vulnerabilities'];

            if ( $vulnerabilities ) :
              foreach ( $vulnerabilities as $vulnerability ) :
                // Check against current version and warn if bad!
                if ( (float) $plugin['Version'] <= (float) $vulnerability['fixed_in'] ) :
                  echo '<h3 style="color: #D54E21;">' . __( 'There is an vulnerability in the version you are using.', 'odd-scanner' ) . '</h3>';
                  echo '<p>' . $vulnerability['title'] . '</p>';

                  if ( $vulnerability['references'] ) :
                    echo '<h4>' . __( 'References', 'odd-scanner' ) . '</h4>';

                    echo '<ul>';
                      foreach ( $vulnerability['references']['url'] as $reference ) :
                        echo '<li><a href="' . $reference . '" target="_blank">' . $reference . '</a></li>';
                      endforeach;
                    echo '</ul>';

                    echo '<a href="plugins.php" class="button button-primary">' . __( 'Update now', 'odd-scanner' ) . '</a>';
                  endif;
                else :
                  echo '<p>' . __( 'Could not find any vulnerabilities for the version you are using.', 'odd-scanner' ) . '</p>';
                endif;
              endforeach;
            else :
              echo '<p>' . __( 'Could not find any vulnerabilities for this plugin.', 'odd-scanner' ) . '</p>';
            endif;

            echo '<p><i>' . __( 'Information updated:', 'odd-scanner' ) . ' ' . date_i18n( get_option( 'date_format' ), strtotime( $wpvulndb['last_updated'] ) ) . ' ' . date_i18n( get_option( 'time_format' ), strtotime( $wpvulndb['last_updated'] ) ) . '</i></p>';
          else :
            echo '<p>' . __( 'Could not find any information about this plugin.', 'odd-scanner' ) . '</p>';
          endif;
        endforeach;
      ?>
    </div>
    <?php
	}


  private function scan_plugins() {
    // Check if get_plugins() function exists. This is required on the front
    // end of the site, since it is in a file that is normally only
    // loaded in the admin.
    if ( ! function_exists( 'get_plugins' ) ) {
    	require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }

    $all_plugins = get_plugins();

    // Loop over the plugin list and get information from the wpvulndb
    foreach ($all_plugins as $plugin_key => $plugin) :
      if ( false === ( $all_plugins[$plugin_key]['wpvulndb'] = json_decode( get_transient( $this->transient_name . '-' . strtoupper( sanitize_title( $plugin['Name'] ) ) ), true ) ) ) :
        $request = wp_remote_get('https://wpvulndb.com/api/v2/plugins/' . sanitize_title( $plugin['Name'] ));

        // We are only intressted in the requests that are not 404
        if ( wp_remote_retrieve_response_code($request) !== 404 ) :
          $all_plugins[$plugin_key]['wpvulndb'] = json_decode(wp_remote_retrieve_body($request), true);

          // Save the result in an transient so we don't spam the poor guys
          set_transient( $this->transient_name . '-' . strtoupper(sanitize_title( $plugin['Name'] )), wp_remote_retrieve_body($request), HOUR_IN_SECONDS );
        endif;
      endif;
    endforeach;

    return $all_plugins;
  }
}

$oddscanner = new OddScanner;
