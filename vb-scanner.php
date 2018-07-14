<?php
/*
Plugin Name: Vulnerability Scanner
Plugin URI: https://wheresmar.co
Description: This plugin checks all your installed plugins with the <a href="https://wpvulndb.com">WPScan Vulnerability Database</a> for known vulnerabilities.
Version: 1.0
Author: Marco Hyyryläinen
Author URI: https://wheresmar.co
Text Domain: vb-scanner
Domain Path: /languages
*/

class VBScanner {

  /**
   * The prefix of the transient that will be used to cache data.
   *
   * @since    1.0.0
   * @access   private
   * @var      string    $transient_name  The transient name
   */
  private $transient_name = 'VB-SCANNER';

  /**
   * Initialize the class and set its properties.
   *
   * @since    1.0.0
   */
  function __construct() {

    // Start upp the textdomain to make it i18n
    add_action( 'plugins_loaded', function() {
      load_plugin_textdomain( 'vb-scanner', FALSE, basename( dirname( __FILE__ ) ) . '/languages/' );
    } );

    // Set the admin menu item and the page for it
    add_action( 'admin_menu', function() {
      add_options_page(
        'Vulnerability Scanner',
        'Vulnerability Scanner',
        'manage_options',
        'vb-scanner',
        array(
          $this,
          'settings_page'
        )
      );
    } );

  }

  /**
   * Displays a settings page that lists all the plugins and there vulnerabilities
   *
   * @since    1.0.0
   */
  function settings_page() {

    $plugins = $this->scan_plugins();

    // Force WP to check plugins for updates and get the info
    do_action( "wp_update_plugins" );
    $update_plugins = get_site_transient( 'update_plugins' );
    ?>
    <div class="wrap">
      <h1>Vulnerability Scanner</h1>
      <p><?php _e( 'This plugin checks all your installed plugins with the <a href="https://wpvulndb.com">WPScan Vulnerability Database</a>. It does not contain information about every plugin and the information may be inaccurate.<br /> To be on the safe side you should always be running the latest version of your plugins.', 'vb-scanner' ); ?></p>

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
                  echo '<h3 style="color: #D54E21;">' . __( 'There is an vulnerability in the version you are using.', 'vb-scanner' ) . '</h3>';
                  echo '<p>' . $vulnerability['title'] . '</p>';

                  if ( $vulnerability['references'] ) :
                    echo '<h4>' . __( 'References', 'vb-scanner' ) . '</h4>';

                    echo '<ul>';
                      foreach ( $vulnerability['references']['url'] as $reference ) :
                        echo '<li><a href="' . $reference . '" target="_blank">' . $reference . '</a></li>';
                      endforeach;
                    echo '</ul>';

                    if ($update_plugins->response) :
                      $response = array_values($update_plugins->response)[0];
                      if (strpos($response->plugin, sanitize_title( $plugin['Name'] )) !== false) :
                        _e( '<h4>There is an update to this plugin</h4>', 'vb-scanner' );
                        echo '<a href="plugins.php" class="button button-primary">' . __( 'Update now', 'vb-scanner' ) . '</a>';
                      else :
                        _e( '<h4>There is no update to this plugin</h4>', 'vb-scanner' );
                      endif;
                    endif;
                  endif;
                else :
                  echo '<p>' . __( 'Could not find any vulnerabilities for the version you are using.', 'vb-scanner' ) . '</p>';
                endif;
              endforeach;
            else :
              echo '<p>' . __( 'Could not find any vulnerabilities for this plugin.', 'vb-scanner' ) . '</p>';
            endif;

            echo '<p><i>' . __( 'Information updated:', 'vb-scanner' ) . ' ' . date_i18n( get_option( 'date_format' ), strtotime( $wpvulndb['last_updated'] ) ) . ' ' . date_i18n( get_option( 'time_format' ), strtotime( $wpvulndb['last_updated'] ) ) . '</i></p>';
          else :
            echo '<p>' . __( 'Could not find any information about this plugin.', 'vb-scanner' ) . '</p>';
          endif;
        endforeach;
      ?>
    </div>
    <?php

  }

  /**
   * Scans the plugins that are on the site for vulnerabilities
   *
   * @since    1.0.0
   */
  private function scan_plugins() {

    // Check if get_plugins() function exists.
    if ( ! function_exists( 'get_plugins' ) ) {
      require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }

    $all_plugins = get_plugins();

    // Loop over the plugin list and get information from the wpvulndb
    foreach ($all_plugins as $plugin_key => $plugin) :
      if ( NULL === ( $all_plugins[$plugin_key]['wpvulndb'] = json_decode( get_transient( $this->transient_name . '-' . strtoupper( sanitize_title( $plugin['Name'] ) ) ), true ) ) ) :
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

$vbscanner = new VBScanner;
