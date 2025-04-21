<?php
/*
Plugin Name: پلاگین برزو
Description: A plugin to generate and manage a secret key for users and verify their signup or purchases for Borrzu.com.
Version: 1.0
Author: Borrzu.com
*/

// Prevent direct access to the file
if (!defined('ABSPATH')) {
    exit;
}

// Generate a secret key for the user
function uvp_generate_secret_key($user_id) {
    // Add capability check
    if (!current_user_can('edit_user', $user_id)) {
        return false;
    }
    $secret_key = wp_generate_password(32, false);  
    update_user_meta($user_id, 'uvp_secret_key', $secret_key);
    return $secret_key;
}

// Delete the secret key for the user
function uvp_delete_secret_key($user_id) {
    delete_user_meta($user_id, 'uvp_secret_key');
}

// Add secret key management to the user profile
function uvp_add_secret_key_to_profile($user) {
    // Check if current user can edit this profile
    if (!current_user_can('edit_user', $user->ID)) {
        return;
    }
    
    $user_id = $user->ID;
    $secret_key = get_user_meta($user_id, 'uvp_secret_key', true);

    // Sanitize POST data
    $action = isset($_POST['uvp_secret_key_action']) ? sanitize_text_field($_POST['uvp_secret_key_action']) : '';
    
    // Use separate nonces for different actions
    if ($action === 'regenerate' && check_admin_referer('uvp_regenerate_key')) {
        $secret_key = uvp_generate_secret_key($user_id);
        if ($secret_key) {
            add_settings_error('uvp_messages', 'uvp_message', 'کلید مخفی با موفقیت بازسازی شد.', 'success');
        }
    } elseif ($action === 'delete' && check_admin_referer('uvp_delete_key')) {
        uvp_delete_secret_key($user_id);
        $secret_key = '';
        add_settings_error('uvp_messages', 'uvp_message', 'کلید مخفی با موفقیت حذف شد.', 'success');
    }

    // Display admin notices properly
    settings_errors('uvp_messages');

    ?>
    <div class="borrzu-secret-key-section">
        <h3>
            <img src="https://borrzu-public.storage.c2.liara.space/assets/logo.svg" alt="Borrzu Logo" style="width: 24px; vertical-align: middle;">
            مدیریت کلید مخفی Borrzu
        </h3>
        <table class="form-table">
            <tr>
                <th><label for="uvp_secret_key">کلید مخفی</label></th>
                <td>
                    <?php if (!empty($secret_key)) : ?>
                        <input type="text" id="uvp_secret_key" value="<?php echo esc_attr($secret_key); ?>" class="regular-text" readonly>
                        <button type="button" onclick="copyToClipboard('uvp_secret_key')" class="button button-secondary">کپی کلید</button>
                        <p class="description">این کلید برای تأیید هویت شما در Borrzu استفاده می‌شود. آن را با دقت نگه دارید.</p>
                    <?php else : ?>
                        <p class="description">هیچ کلید مخفی‌ای وجود ندارد. برای ایجاد یک کلید جدید، دکمه "بازسازی کلید" را بزنید.</p>
                    <?php endif; ?>
                </td>
            </tr>
        </table>
        <form method="post" action="">
            <?php wp_nonce_field('uvp_regenerate_key', 'uvp_nonce'); ?>
            <input type="hidden" name="uvp_secret_key_action" value="regenerate">
            <button type="submit" class="button button-primary">بازسازی کلید</button>
        </form>
        <?php if (!empty($secret_key)) : ?>
            <form method="post" action="" style="margin-top: 10px;">
                <?php wp_nonce_field('uvp_delete_key', 'uvp_nonce'); ?>
                <input type="hidden" name="uvp_secret_key_action" value="delete">
                <button type="submit" class="button button-danger" onclick="return confirm('آیا مطمئن هستید که می‌خواهید کلید مخفی را حذف کنید؟')">حذف کلید</button>
            </form>
        <?php endif; ?>
    </div>
    <script>
    async function copyToClipboard(elementId) {
        try {
            const copyText = document.getElementById(elementId);
            if (!copyText) return;
            
            await navigator.clipboard.writeText(copyText.value);
            // Use WordPress admin notices style
            const notice = document.createElement('div');
            notice.className = 'notice notice-success is-dismissible';
            notice.innerHTML = '<p>کلید مخفی با موفقیت کپی شد.</p>';
            
            const targetElement = document.querySelector('.borrzu-secret-key-section');
            targetElement.insertBefore(notice, targetElement.firstChild);
            
            setTimeout(() => notice.remove(), 3000);
        } catch (err) {
            console.error('Copy failed:', err);
        }
    }
    </script>
    <style>
        .borrzu-secret-key-section {
            background: #f9f9f9;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 5px;
            margin-top: 20px;
        }
        .borrzu-secret-key-section h3 {
            margin-top: 0;
            font-size: 1.5em;
            color: #333;
        }
        .button-danger {
            background-color: #dc3545;
            border-color: #dc3545;
            color: #fff;
        }
        .button-danger:hover {
            background-color: #c82333;
            border-color: #bd2130;
        }
    </style>
    <?php
}
add_action('show_user_profile', 'uvp_add_secret_key_to_profile');
add_action('edit_user_profile', 'uvp_add_secret_key_to_profile');

// Add rate limiting for key generation
function uvp_check_rate_limit($user_id) {
    $last_generation = get_user_meta($user_id, 'uvp_last_key_generation', true);
    $current_time = time();
    
    if ($last_generation && ($current_time - $last_generation) < 300) { // 5 minutes
        return false;
    }
    
    update_user_meta($user_id, 'uvp_last_key_generation', $current_time);
    return true;
}

function uvp_encrypt_key($key) {
    if (!function_exists('openssl_encrypt')) return $key;
    
    $encryption_key = wp_salt('auth');
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('AES-256-CBC'));
    
    $encrypted = openssl_encrypt($key, 'AES-256-CBC', $encryption_key, 0, $iv);
    return base64_encode($iv . $encrypted);
}

register_activation_hook(__FILE__, 'uvp_activation_check');
function uvp_activation_check() {
    if (version_compare(PHP_VERSION, '7.4', '<')) {
        deactivate_plugins(plugin_basename(__FILE__));
        wp_die('این افزونه نیاز به PHP نسخه 7.4 یا بالاتر دارد.');
    }
}

if (!is_ssl()) {
    wp_die('این عملیات نیاز به اتصال SSL دارد.');
}

// Add table for API logs on plugin activation
register_activation_hook(__FILE__, 'uvp_create_logs_table');
function uvp_create_logs_table() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'borrzu_api_logs';
    
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE IF NOT EXISTS $table_name (
        id bigint(20) NOT NULL AUTO_INCREMENT,
        user_id bigint(20) NOT NULL,
        endpoint varchar(255) NOT NULL,
        headers text,
        request_data text,
        response_data text,
        status_code int(11),
        created_at datetime DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY  (id)
    ) $charset_collate;";

    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);
}

// Modify the uvp_log_api_call function to better handle the data
function uvp_log_api_call($user_id, $endpoint, $headers, $request_data, $response_data, $status_code) {
    global $wpdb;
    $table_name = $wpdb->prefix . 'borrzu_api_logs';
    
    // Convert headers to string if it's an object or array
    if (is_object($headers) || is_array($headers)) {
        $headers = json_encode($headers, JSON_UNESCAPED_UNICODE);
    }

    // Convert request data to string
    if (is_array($request_data) || is_object($request_data)) {
        $request_data = json_encode($request_data, JSON_UNESCAPED_UNICODE);
    }

    // Convert response data to string
    if (is_array($response_data) || is_object($response_data)) {
        $response_data = json_encode($response_data, JSON_UNESCAPED_UNICODE);
    }

    // Insert log
    $result = $wpdb->insert(
        $table_name,
        array(
            'user_id' => $user_id,
            'endpoint' => $endpoint,
            'headers' => $headers,
            'request_data' => $request_data,
            'response_data' => $response_data,
            'status_code' => $status_code,
            'created_at' => current_time('mysql')
        ),
        array('%d', '%s', '%s', '%s', '%s', '%d', '%s')
    );

    if ($result === false) {
        error_log('Borrzu API Log Error: ' . $wpdb->last_error);
    }

    return $result;
}

// Function to make API calls with logging
function uvp_make_api_call($endpoint, $method = 'GET', $data = null, $headers = array()) {
    $user_id = get_current_user_id();
    $start_time = microtime(true);
    
    // Prepare the request
    $args = array(
        'method'      => $method,
        'timeout'     => 30,
        'redirection' => 5,
        'headers'     => $headers,
        'sslverify'   => true
    );

    if ($data !== null) {
        $args['body'] = is_array($data) ? json_encode($data) : $data;
    }

    // Make the API call
    $response = wp_remote_request($endpoint, $args);
    
    // Get response data
    $status_code = wp_remote_retrieve_response_code($response);
    $response_body = wp_remote_retrieve_body($response);
    $response_headers = wp_remote_retrieve_headers($response);
    
    // Log the API call
    uvp_log_api_call(
        $user_id,
        $endpoint,
        $headers,
        $data,
        array(
            'body' => $response_body,
            'headers' => $response_headers,
            'status' => $status_code,
            'duration' => round((microtime(true) - $start_time) * 1000, 2) // Duration in milliseconds
        ),
        $status_code
    );

    // Return the response
    if (is_wp_error($response)) {
        return array(
            'success' => false,
            'status_code' => 500,
            'message' => $response->get_error_message(),
            'data' => null
        );
    }

    return array(
        'success' => $status_code >= 200 && $status_code < 300,
        'status_code' => $status_code,
        'message' => wp_remote_retrieve_response_message($response),
        'data' => json_decode($response_body, true)
    );
}

// Function to handle API errors and logging
function uvp_handle_api_error($response, $endpoint) {
    if (!$response['success']) {
        // Log error to WordPress error log
        error_log(sprintf(
            '[Borrzu API Error] Endpoint: %s, Status: %d, Message: %s',
            $endpoint,
            $response['status_code'],
            $response['message']
        ));

        // Add admin notice for admin users
        if (current_user_can('manage_options')) {
            add_action('admin_notices', function() use ($response) {
                ?>
                <div class="notice notice-error is-dismissible">
                    <p>
                        <strong>خطا در API برزو:</strong>
                        <?php echo esc_html($response['message']); ?>
                        (کد خطا: <?php echo esc_html($response['status_code']); ?>)
                    </p>
                </div>
                <?php
            });
        }

        return false;
    }
    return true;
}

// Example usage:
function uvp_example_api_call() {
    $endpoint = 'https://api.borrzu.com/v1/endpoint';
    $headers = array(
        'X-Borrzu-Auth' => get_user_meta(get_current_user_id(), 'uvp_secret_key', true),
        'Content-Type' => 'application/json'
    );
    $data = array('key' => 'value');

    $response = uvp_make_api_call($endpoint, 'POST', $data, $headers);
    
    // Handle any errors
    if (!uvp_handle_api_error($response, $endpoint)) {
        return false;
    }

    // Process successful response
    return $response['data'];
}

// Modify the uvp_enhance_api_log_display function to remove collapsible details
function uvp_enhance_api_log_display($log) {
    $response_data = json_decode($log->response_data, true);
    $request_data = json_decode($log->request_data, true);
    $headers = json_decode($log->headers, true);
    $status_code = $log->status_code;
    $duration = isset($response_data['duration']) ? $response_data['duration'] : null;
    
    $status_class = ($status_code >= 200 && $status_code < 300) ? 'success' : 'failed';
    ?>
    <div class="log-item <?php echo esc_attr($status_class); ?>">
        <div class="log-header">
            <div class="log-header-left">
                <span class="method"><?php echo esc_html($request_data['method'] ?? 'GET'); ?></span>
                <span class="endpoint"><?php echo esc_html($log->endpoint); ?></span>
            </div>
            <div class="log-header-right">
                <span class="status-code"><?php echo esc_html($status_code); ?></span>
                <?php if ($duration): ?>
                    <span class="duration"><?php echo esc_html($duration); ?>ms</span>
                <?php endif; ?>
                <span class="date"><?php echo wp_date('Y/m/d H:i', strtotime($log->created_at)); ?></span>
                <button class="view-details button button-small">مشاهده جزئیات</button>
            </div>
        </div>
        
        <!-- Hidden container for modal data -->
        <div class="log-details" style="display: none;">
            <div class="tab-content" id="request-tab">
                <div class="detail-section">
                    <h4>داده‌های درخواست:</h4>
                    <pre><?php echo esc_html(json_encode($request_data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)); ?></pre>
                </div>
            </div>
            <div class="tab-content" id="response-tab">
                <div class="detail-section">
                    <h4>داده‌های پاسخ:</h4>
                    <pre><?php echo esc_html(json_encode($response_data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)); ?></pre>
                </div>
            </div>
            <div class="tab-content" id="headers-tab">
                <div class="detail-section">
                    <h4>هدرهای درخواست:</h4>
                    <pre><?php echo esc_html(json_encode($headers, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)); ?></pre>
                </div>
            </div>
        </div>
    </div>
    <?php
}

// Update the filter section styles and layout
function uvp_add_filter_styles() {
    ?>
    <style>
        /* Enhanced Filter Styles */
        .borrzu-filter-card {
            background: white;
            border-radius: 12px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            padding: 24px;
            margin-bottom: 24px;
        }
        .filter-form {
            display: flex;
            flex-direction: column;
            gap: 20px;
        }
        .filter-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 24px;
            align-items: end;
        }
        .filter-group {
            position: relative;
        }
        .filter-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: #374151;
            font-size: 0.9rem;
        }
        .filter-group input,
        .filter-group select {
            width: 100%;
            padding: 10px 12px;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            font-size: 0.95rem;
            transition: all 0.2s ease;
            background-color: #f9fafb;
        }
        .filter-group input:focus,
        .filter-group select:focus {
            border-color: #2271b1;
            box-shadow: 0 0 0 2px rgba(34, 113, 177, 0.1);
            outline: none;
            background-color: #fff;
        }
        .filter-group input::placeholder {
            color: #9ca3af;
        }
        .filter-actions {
            display: flex;
            gap: 12px;
            justify-content: flex-end;
            padding-top: 8px;
            border-top: 1px solid #e5e7eb;
        }
        .filter-actions .button {
            padding: 8px 16px;
            height: auto;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            font-size: 0.95rem;
        }
        .filter-actions .button-primary {
            background: #2271b1;
            border-color: #2271b1;
        }
        .filter-actions .button-primary:hover {
            background: #135e96;
            border-color: #135e96;
        }
        .filter-actions .button-reset {
            color: #4b5563;
            border-color: #e5e7eb;
        }
        .filter-actions .button-reset:hover {
            background: #f3f4f6;
            border-color: #d1d5db;
        }
        
        /* Enhanced Log Item Styles */
        .log-item {
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            margin-bottom: 12px;
            background: white;
            transition: all 0.2s ease;
        }
        .log-item:hover {
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
        }
        .log-header {
            padding: 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }
        .view-details {
            padding: 6px 12px;
            font-size: 0.85rem;
            height: auto;
            line-height: 1.2;
            background: #f3f4f6;
            border-color: #e5e7eb;
            color: #4b5563;
        }
        .view-details:hover {
            background: #e5e7eb;
            border-color: #d1d5db;
        }
        
        /* Modal Enhancements */
        .borrzu-modal {
            backdrop-filter: blur(4px);
        }
        .modal-content {
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
        }
        .modal-header {
            background: #f9fafb;
            border-radius: 12px 12px 0 0;
        }
        .close-modal {
            width: 32px;
            height: 32px;
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.2s ease;
        }
        .close-modal:hover {
            background: #e5e7eb;
        }
    </style>

    <script>
    jQuery(document).ready(function($) {
        // Show modal when clicking view details button
        $('.view-details').click(function(e) {
            e.preventDefault();
            e.stopPropagation();
            
            const logItem = $(this).closest('.log-item');
            const requestData = logItem.find('#request-tab').html();
            const responseData = logItem.find('#response-tab').html();
            const headersData = logItem.find('#headers-tab').html();
            
            // Populate modal content
            $('#modal-request-tab').html(requestData);
            $('#modal-response-tab').html(responseData);
            $('#modal-headers-tab').html(headersData);
            
            // Show first tab
            $('#log-detail-modal .tab-content').hide();
            $('#modal-request-tab').show();
            $('#log-detail-modal .tab-button').first().addClass('active')
                .siblings().removeClass('active');
            
            // Show modal
            $('#log-detail-modal').fadeIn(200);
        });
        
        // Close modal with escape key
        $(document).keydown(function(e) {
            if (e.keyCode === 27) { // escape key
                $('#log-detail-modal').fadeOut(200);
            }
        });
    });
    </script>
    <?php
}
add_action('admin_footer', 'uvp_add_filter_styles');

// Add submenu for API logs
function uvp_add_admin_menu() {
    // Get and encode the SVG content
    $svg_url = 'https://borrzu-public.storage.c2.liara.space/assets/logo.svg';
    $svg_content = file_get_contents($svg_url);
    
    // Add main menu page
    add_menu_page(
        'برزو - مدیریت کلید مخفی',    // Page title
        'برزو',                        // Menu title
        'read',                        // Capability
        'borrzu-secret-key',          // Menu slug
        'uvp_admin_page',             // Function to display the page
        'data:image/svg+xml;base64,' . base64_encode($svg_content), // Menu icon
        30                            // Position
    );
    
    // Rename the default submenu item
    add_submenu_page(
        'borrzu-secret-key',
        'مدیریت کلید‌ها',             // Page title
        'مدیریت کلید‌ها',             // Menu title
        'read',
        'borrzu-secret-key',          // Same as parent slug
        'uvp_admin_page'
    );
    
    // Add API logs submenu
    add_submenu_page(
        'borrzu-secret-key',
        'گزارش‌های API',
        'گزارش‌های API',
        'read',
        'borrzu-api-logs',
        'uvp_api_logs_page'
    );
}
add_action('admin_menu', 'uvp_add_admin_menu');

// Add this CSS to adjust the menu icon size and color
function uvp_admin_menu_style() {
    ?>
    <style>
        #adminmenu .toplevel_page_borrzu-secret-key .wp-menu-image img {
            width: 20px;
            height: 20px;
            padding: 7px 0;
            opacity: 1;
        }
        /* Adjust icon for dark mode */
        .admin-color-light #adminmenu .toplevel_page_borrzu-secret-key .wp-menu-image img {
            filter: brightness(0.3);
        }
    </style>
    <?php
}
add_action('admin_head', 'uvp_admin_menu_style');

// Modify the API logs page query to show all logs
function uvp_api_logs_page() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'borrzu_api_logs';
    
    // Get filter values
    $endpoint_filter = isset($_GET['endpoint']) ? sanitize_text_field($_GET['endpoint']) : '';
    $status_filter = isset($_GET['status']) ? sanitize_text_field($_GET['status']) : '';
    $date_from = isset($_GET['date_from']) ? sanitize_text_field($_GET['date_from']) : '';
    $date_to = isset($_GET['date_to']) ? sanitize_text_field($_GET['date_to']) : '';
    
    // Build query
    $where_clauses = array();
    $where_values = array();
    
    if (!empty($endpoint_filter)) {
        $where_clauses[] = 'endpoint LIKE %s';
        $where_values[] = '%' . $wpdb->esc_like($endpoint_filter) . '%';
    }
    
    if (!empty($status_filter)) {
        $where_clauses[] = 'status_code = %d';
        $where_values[] = intval($status_filter);
    }
    
    if (!empty($date_from)) {
        $where_clauses[] = 'created_at >= %s';
        $where_values[] = $date_from . ' 00:00:00';
    }
    
    if (!empty($date_to)) {
        $where_clauses[] = 'created_at <= %s';
        $where_values[] = $date_to . ' 23:59:59';
    }
    
    // Pagination
    $per_page = 20;
    $current_page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
    $offset = ($current_page - 1) * $per_page;
    
    // Construct final query
    $query = "SELECT * FROM $table_name";
    if (!empty($where_clauses)) {
        $query .= ' WHERE ' . implode(' AND ', $where_clauses);
    }
    $query .= ' ORDER BY created_at DESC LIMIT %d OFFSET %d';
    $where_values[] = $per_page;
    $where_values[] = $offset;
    
    $logs = $wpdb->get_results($wpdb->prepare($query, $where_values));
    $total_items = $wpdb->get_var("SELECT COUNT(*) FROM $table_name");
    
    ?>
    <div class="wrap borrzu-wrap">
        <h1>
            <img src="https://borrzu-public.storage.c2.liara.space/assets/logo.svg" alt="لوگو برزو" style="width: 32px; vertical-align: middle; margin-left: 10px;">
            گزارش‌های API برزو
        </h1>

        <div class="borrzu-tabs">
            <a href="?page=borrzu-secret-key" class="tab-item">مدیریت کلید</a>
            <a href="?page=borrzu-api-logs" class="tab-item active">گزارش‌های API</a>
        </div>

        <!-- Filter Section -->
        <div class="borrzu-filter-card">
            <form method="get" class="filter-form">
                <input type="hidden" name="page" value="borrzu-api-logs">
                
                <div class="filter-row">
                    <div class="filter-group">
                        <label for="endpoint">آدرس API:</label>
                        <input type="text" id="endpoint" name="endpoint" value="<?php echo esc_attr($endpoint_filter); ?>" placeholder="جستجو در آدرس‌ها...">
                    </div>
                    
                    <div class="filter-group">
                        <label for="status">وضعیت:</label>
                        <select id="status" name="status">
                            <option value="">همه</option>
                            <option value="200" <?php selected($status_filter, '200'); ?>>موفق (200)</option>
                            <option value="400" <?php selected($status_filter, '400'); ?>>خطای درخواست (400)</option>
                            <option value="401" <?php selected($status_filter, '401'); ?>>عدم دسترسی (401)</option>
                            <option value="404" <?php selected($status_filter, '404'); ?>>یافت نشد (404)</option>
                            <option value="500" <?php selected($status_filter, '500'); ?>>خطای سرور (500)</option>
                        </select>
                    </div>
                    
                    <div class="filter-group">
                        <label for="date_from">از تاریخ:</label>
                        <input type="date" id="date_from" name="date_from" value="<?php echo esc_attr($date_from); ?>">
                    </div>
                    
                    <div class="filter-group">
                        <label for="date_to">تا تاریخ:</label>
                        <input type="date" id="date_to" name="date_to" value="<?php echo esc_attr($date_to); ?>">
                    </div>
                </div>
                
                <div class="filter-actions">
                    <button type="submit" class="button button-primary">اعمال فیلتر</button>
                    <a href="?page=borrzu-api-logs" class="button">پاک کردن فیلترها</a>
                </div>
            </form>
        </div>

        <div class="borrzu-card">
            <?php if (empty($logs)) : ?>
                <div class="borrzu-empty-state">
                    <div class="empty-state-icon">
                        <svg width="120" height="120" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                            <path d="M21 7V17C21 18.1046 20.1046 19 19 19H5C3.89543 19 3 18.1046 3 17V7C3 5.89543 3.89543 5 5 5H19C20.1046 5 21 5.89543 21 7Z" stroke="#9CA3AF" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
                            <path d="M3 7L12 13L21 7" stroke="#9CA3AF" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
                            <circle cx="12" cy="12" r="8" fill="#F3F4F6" stroke="#9CA3AF" stroke-width="1.5"/>
                            <path d="M12 8V12M12 14V16" stroke="#9CA3AF" stroke-width="2" stroke-linecap="round"/>
                        </svg>
                    </div>
                    <h3>بدون گزارش</h3>
                    <p>هنوز هیچ درخواست API‌ای ثبت نشده است</p>
                </div>
            <?php else : ?>
                <div class="borrzu-logs-table">
                    <?php foreach ($logs as $log) : ?>
                        <?php uvp_enhance_api_log_display($log); ?>
                    <?php endforeach; ?>
                </div>
                
                <?php
                $total_pages = ceil($total_items / $per_page);
                if ($total_pages > 1) :
                    echo paginate_links(array(
                        'base' => add_query_arg('paged', '%#%'),
                        'format' => '',
                        'prev_text' => __('&laquo;'),
                        'next_text' => __('&raquo;'),
                        'total' => $total_pages,
                        'current' => $current_page
                    ));
                endif;
                ?>
            <?php endif; ?>
        </div>
    </div>

    <!-- Modal Template -->
    <div id="log-detail-modal" class="borrzu-modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2>جزئیات لاگ</h2>
                <button class="close-modal">&times;</button>
            </div>
            <div class="modal-body">
                <div class="log-tabs">
                    <button class="tab-button active" data-tab="request">درخواست</button>
                    <button class="tab-button" data-tab="response">پاسخ</button>
                    <button class="tab-button" data-tab="headers">هدرها</button>
                </div>
                <div class="tab-content" id="modal-request-tab"></div>
                <div class="tab-content" id="modal-response-tab"></div>
                <div class="tab-content" id="modal-headers-tab"></div>
            </div>
        </div>
    </div>

    <style>
        .borrzu-wrap {
            direction: rtl;
            max-width: 1200px;
            margin: 20px auto;
            font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
        }
        .borrzu-tabs {
            margin: 20px 0;
            border-bottom: 1px solid #ddd;
        }
        .tab-item {
            display: inline-block;
            padding: 10px 20px;
            text-decoration: none;
            color: #666;
            border-bottom: 2px solid transparent;
            margin-bottom: -1px;
        }
        .tab-item.active {
            color: #2271b1;
            border-bottom-color: #2271b1;
        }
        .borrzu-card {
            background: white;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            padding: 20px;
        }
        .borrzu-empty-state {
            text-align: center;
            padding: 60px 20px;
            background: #fff;
            border-radius: 8px;
        }
        .empty-state-icon {
            margin-bottom: 20px;
        }
        .empty-state-icon svg {
            width: 120px;
            height: 120px;
        }
        .borrzu-empty-state h3 {
            color: #374151;
            font-size: 1.5em;
            margin: 0 0 10px 0;
        }
        .borrzu-empty-state p {
            color: #6B7280;
            font-size: 1.1em;
            margin: 0;
        }
        .log-item {
            border: 1px solid #ddd;
            border-radius: 4px;
            margin-bottom: 10px;
        }
        .log-header {
            padding: 15px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .log-item.success .log-header {
            background-color: #f0f9f0;
        }
        .log-item.failed .log-header {
            background-color: #fef0f0;
        }
        .endpoint {
            font-weight: bold;
        }
        .status-code {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
        }
        .success .status-code {
            background: #d4edda;
            color: #155724;
        }
        .error .status-code {
            background: #f8d7da;
            color: #721c24;
        }
        .log-details {
            padding: 15px;
            border-top: 1px solid #ddd;
            background: #f8f9fa;
        }
        .detail-section {
            margin-bottom: 15px;
        }
        .detail-section h4 {
            margin: 0 0 10px 0;
            color: #666;
        }
        pre {
            background: #fff;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
            margin: 0;
        }
        .borrzu-pagination {
            margin-top: 20px;
            text-align: center;
        }
        
        /* Filter Styles */
        .borrzu-filter-card {
            background: white;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            padding: 20px;
            margin-bottom: 20px;
        }
        .filter-form {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }
        .filter-row {
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
        }
        .filter-group {
            flex: 1;
            min-width: 200px;
        }
        .filter-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
            color: #495057;
        }
        .filter-group input,
        .filter-group select {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        .filter-actions {
            display: flex;
            gap: 10px;
            justify-content: flex-end;
        }
        
        /* Modal Styles */
        .borrzu-modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.5);
            z-index: 100000;
            padding: 20px;
        }
        .modal-content {
            background: white;
            border-radius: 8px;
            max-width: 900px;
            margin: 40px auto;
            max-height: 80vh;
            overflow-y: auto;
        }
        .modal-header {
            padding: 15px 20px;
            border-bottom: 1px solid #ddd;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .modal-header h2 {
            margin: 0;
            font-size: 1.5em;
        }
        .close-modal {
            background: none;
            border: none;
            font-size: 24px;
            cursor: pointer;
            color: #666;
        }
        .modal-body {
            padding: 20px;
        }
        .modal-body .log-tabs {
            position: sticky;
            top: 0;
            background: white;
            z-index: 1;
        }
    </style>

    <script>
    jQuery(document).ready(function($) {
        // Show modal when clicking on log item
        $('.log-header').click(function() {
            const logItem = $(this).closest('.log-item');
            const requestData = logItem.find('#request-tab').html();
            const responseData = logItem.find('#response-tab').html();
            const headersData = logItem.find('#headers-tab').html();
            
            // Populate modal content
            $('#modal-request-tab').html(requestData);
            $('#modal-response-tab').html(responseData);
            $('#modal-headers-tab').html(headersData);
            
            // Show modal
            $('#log-detail-modal').fadeIn(200);
            
            // Prevent event bubbling
            return false;
        });
        
        // Close modal
        $('.close-modal, .borrzu-modal').click(function(e) {
            if (e.target === this) {
                $('#log-detail-modal').fadeOut(200);
            }
        });
        
        // Modal tab switching
        $('#log-detail-modal .tab-button').click(function() {
            const tabId = $(this).data('tab');
            
            // Update active tab button
            $(this).siblings().removeClass('active');
            $(this).addClass('active');
            
            // Show selected tab content
            $('#log-detail-modal .tab-content').hide();
            $(`#modal-${tabId}-tab`).show();
        });
        
        // Show first tab by default
        $('#log-detail-modal .tab-content').hide();
        $('#modal-request-tab').show();
    });
    </script>
    <?php
}

// محتوای صفحه مدیریت
function uvp_admin_page() {
    $user_id = get_current_user_id();
    $secret_key = get_user_meta($user_id, 'uvp_secret_key', true);
    
    // بررسی فرم‌های ارسالی
    if (isset($_POST['uvp_secret_key_action'])) {
        $action = sanitize_text_field($_POST['uvp_secret_key_action']);
        
        if ($action === 'regenerate') {
            check_admin_referer('uvp_secret_key_action', 'uvp_nonce');
            $secret_key = uvp_generate_secret_key($user_id);
            if ($secret_key) {
                add_settings_error('uvp_messages', 'uvp_message', 'کلید مخفی با موفقیت ساخته شد.', 'success');
            }
        } elseif ($action === 'delete') {
            check_admin_referer('uvp_secret_key_action', 'uvp_nonce');
            uvp_delete_secret_key($user_id);
            $secret_key = '';
            add_settings_error('uvp_messages', 'uvp_message', 'کلید مخفی با موفقیت حذف شد.', 'success');
        }
    }

    settings_errors('uvp_messages');
    ?>
    <div class="wrap borrzu-wrap">
        <h1>
            <img src="https://borrzu-public.storage.c2.liara.space/assets/logo.svg" alt="لوگو برزو" style="width: 32px; vertical-align: middle; margin-left: 10px;">
            برزو
        </h1>

        <div class="borrzu-tabs">
            <a href="?page=borrzu-secret-key" class="tab-item active">مدیریت کلید‌ها</a>
            <a href="?page=borrzu-api-logs" class="tab-item">گزارش‌های API</a>
        </div>

        <div class="borrzu-card">
            <div class="key-status-section">
                <?php if (empty($secret_key)) : ?>
                    <div class="no-key-state">
                        <div class="key-icon">🔑</div>
                        <h2>کلید مخفی ندارید</h2>
                        <p>برای استفاده از API برزو، نیاز به یک کلید مخفی دارید.</p>
                        <form method="post" action="">
                            <?php wp_nonce_field('uvp_secret_key_action', 'uvp_nonce'); ?>
                            <input type="hidden" name="uvp_secret_key_action" value="regenerate">
                            <button type="submit" class="button button-primary button-hero">
                                <span class="dashicons dashicons-plus-alt"></span>
                                ساخت کلید جدید
                            </button>
                        </form>
                    </div>
                <?php else : ?>
                    <div class="has-key-state">
                        <div class="key-header">
                            <div class="key-status">
                                <span class="status-badge">فعال</span>
                                <h2>کلید مخفی شما</h2>
                            </div>
                            <div class="key-actions">
                                <button type="button" onclick="copyToClipboard('uvp_secret_key')" class="button button-secondary">
                                    <span class="dashicons dashicons-clipboard"></span>
                                    کپی کلید
                                </button>
                                <form method="post" action="" style="display: inline-block;">
                                    <?php wp_nonce_field('uvp_secret_key_action', 'uvp_nonce'); ?>
                                    <input type="hidden" name="uvp_secret_key_action" value="regenerate">
                                    <button type="submit" class="button button-secondary">
                                        <span class="dashicons dashicons-update"></span>
                                        بازسازی کلید
                                    </button>
                                </form>
                            </div>
                        </div>
                        
                        <div class="key-display">
                            <input type="text" id="uvp_secret_key" value="<?php echo esc_attr($secret_key); ?>" class="regular-text" readonly>
                        </div>
                        
                        <div class="key-info">
                            <div class="info-item">
                                <span class="dashicons dashicons-shield"></span>
                                <span>این کلید را در جای امنی نگهداری کنید</span>
                            </div>
                            <div class="info-item">
                                <span class="dashicons dashicons-warning"></span>
                                <span>در صورت بازسازی کلید، کلید قبلی غیرفعال خواهد شد</span>
                            </div>
                            <div class="info-item">
                                <span class="dashicons dashicons-admin-network"></span>
                                <span>برای استفاده در API، از هدر <code>X-Borrzu-Auth</code> با مقدار کلید استفاده کنید</span>
                            </div>
                        </div>

                        <div class="danger-zone">
                            <h3>ناحیه خطر</h3>
                            <p>حذف کلید مخفی باعث قطع دسترسی به API خواهد شد.</p>
                            <form method="post" action="">
                                <?php wp_nonce_field('uvp_secret_key_action', 'uvp_nonce'); ?>
                                <input type="hidden" name="uvp_secret_key_action" value="delete">
                                <button type="submit" class="button button-danger" onclick="return confirm('آیا از حذف کلید مخفی خود اطمینان دارید؟')">
                                    <span class="dashicons dashicons-trash"></span>
                                    حذف کلید
                                </button>
                            </form>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <style>
        .borrzu-wrap {
            direction: rtl;
            max-width: 1200px;
            margin: 20px auto;
            font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
        }
        .borrzu-card {
            background: white;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            margin-top: 20px;
        }
        .borrzu-tabs {
            margin: 20px 0;
            border-bottom: 1px solid #ddd;
        }
        .tab-item {
            display: inline-block;
            padding: 10px 20px;
            text-decoration: none;
            color: #666;
            border-bottom: 2px solid transparent;
            margin-bottom: -1px;
        }
        .tab-item.active {
            color: #2271b1;
            border-bottom-color: #2271b1;
        }
        .borrzu-inner-tabs {
            padding: 15px 20px;
            background: #f8f9fa;
            border-bottom: 1px solid #ddd;
            border-radius: 8px 8px 0 0;
        }
        .inner-tab-item {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            text-decoration: none;
            color: #666;
            border-radius: 4px;
            margin-left: 10px;
            transition: all 0.2s ease;
        }
        .inner-tab-item:hover {
            background: #f0f0f1;
            color: #2271b1;
        }
        .inner-tab-item.active {
            background: #2271b1;
            color: white;
        }
        .inner-tab-item .dashicons {
            font-size: 16px;
            width: 16px;
            height: 16px;
            margin-top: 2px;
        }
        .tab-content {
            padding: 20px;
        }
        .key-status-section {
            text-align: center;
        }
        .no-key-state {
            padding: 40px 20px;
        }
        .key-icon {
            font-size: 48px;
            margin-bottom: 20px;
        }
        .has-key-state {
            text-align: right;
        }
        .key-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .key-status h2 {
            margin: 5px 0;
        }
        .status-badge {
            background: #d4edda;
            color: #155724;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            display: inline-block;
        }
        .key-display {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .key-display input {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-family: monospace;
            font-size: 16px;
            background: white;
        }
        .key-info {
            margin: 20px 0;
            padding: 20px;
            background: #fff8e5;
            border-radius: 8px;
        }
        .info-item {
            display: flex;
            align-items: center;
            margin-bottom: 10px;
        }
        .info-item .dashicons {
            margin-left: 10px;
            color: #856404;
        }
        .danger-zone {
            margin-top: 40px;
            padding: 20px;
            background: #fff5f5;
            border-radius: 8px;
            border: 1px dashed #dc3545;
        }
        .danger-zone h3 {
            color: #dc3545;
            margin-top: 0;
        }
        .button {
            display: inline-flex;
            align-items: center;
            gap: 5px;
        }
        .button-danger {
            background: #dc3545 !important;
            border-color: #dc3545 !important;
            color: white !important;
        }
        .button-danger:hover {
            background: #c82333 !important;
            border-color: #bd2130 !important;
        }
        .key-actions {
            display: flex;
            gap: 10px;
        }
        .notice {
            margin: 20px 0 !important;
        }
        /* RTL fixes for dashicons */
        .dashicons {
            transform: scaleX(-1);
        }
    </style>

    <script>
    async function copyToClipboard(elementId) {
        try {
            const copyText = document.getElementById(elementId);
            if (!copyText) return;
            
            await navigator.clipboard.writeText(copyText.value);
            // Use WordPress admin notices style
            const notice = document.createElement('div');
            notice.className = 'notice notice-success is-dismissible';
            notice.innerHTML = '<p>کلید مخفی با موفقیت کپی شد.</p>';
            
            const targetElement = document.querySelector('.borrzu-secret-key-section');
            targetElement.insertBefore(notice, targetElement.firstChild);
            
            setTimeout(() => notice.remove(), 3000);
        } catch (err) {
            console.error('Copy failed:', err);
        }
    }
    </script>
    <?php
}

// Add REST API endpoint for plugin verification
function uvp_register_verification_endpoint() {
    register_rest_route('borrzu/v1', '/verify', array(
        'methods' => 'GET',
        'callback' => 'uvp_verify_plugin',
        'permission_callback' => '__return_true'
    ));
}
add_action('rest_api_init', 'uvp_register_verification_endpoint');

// Modify the verify plugin endpoint to properly log
function uvp_verify_plugin(WP_REST_Request $request) {
    // Include required admin functions
    if (!function_exists('is_plugin_active')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }

    $site_url = get_site_url();
    $plugin_version = '1.0';
    $user_count = count_users();
    
    $is_active = is_plugin_active(plugin_basename(__FILE__));
    $is_woocommerce_active = class_exists('WooCommerce');
    
    global $wpdb;
    $has_active_keys = $wpdb->get_var(
        "SELECT COUNT(*) FROM {$wpdb->usermeta} WHERE meta_key = 'uvp_secret_key' AND meta_value != ''"
    );

    $response = array(
        'status' => 'active',
        'message' => 'پلاگین برزو با موفقیت نصب و فعال شده است',
        'site_url' => $site_url,
        'plugin_version' => $plugin_version,
        'is_active' => $is_active,
        'has_active_keys' => $has_active_keys > 0,
        'total_users' => $user_count['total_users'],
        'woocommerce' => array(
            'is_active' => $is_woocommerce_active,
            'message' => $is_woocommerce_active ? 'ووکامرس فعال است' : 'ووکامرس فعال نیست'
        ),
        'connection_status' => array(
            'connected' => true,
            'message' => 'اتصال به برزو برقرار است'
        )
    );

    // Set status code based on WooCommerce status
    $status_code = $is_woocommerce_active ? 200 : 428; // 428 Precondition Required

    // Log the API call with all headers
    uvp_log_api_call(
        0,
        'verify',
        $request->get_headers(),
        array(
            'method' => 'GET',
            'url' => $request->get_route(),
            'params' => $request->get_params()
        ),
        $response,
        $status_code
    );

    return new WP_REST_Response($response, $status_code);
}

// Add connection status to admin page
function uvp_add_connection_status() {
    $api_url = rest_url('borrzu/v1/verify');
    ?>
    <div class="borrzu-connection-status">
        <div class="status-indicator">
            <span class="status-dot"></span>
            <span class="status-text">در حال بررسی اتصال...</span>
        </div>
    </div>

    <style>
        .borrzu-connection-status {
            margin-top: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            border: 1px solid #ddd;
        }
        .status-indicator {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .status-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #ffc107;
            display: inline-block;
        }
        .status-dot.connected {
            background: #28a745;
        }
        .status-dot.disconnected {
            background: #dc3545;
        }
    </style>

    <script>
    jQuery(document).ready(function($) {
        function checkConnection() {
            $.get('<?php echo esc_url($api_url); ?>', function(response) {
                const statusDot = $('.status-dot');
                const statusText = $('.status-text');
                
                if (response.connection_status.connected) {
                    statusDot.addClass('connected');
                    statusText.text('اتصال به برزو برقرار است');
                } else {
                    statusDot.addClass('disconnected');
                    statusText.text('خطا در اتصال به برزو');
                }
            }).fail(function() {
                $('.status-dot').addClass('disconnected');
                $('.status-text').text('خطا در اتصال به برزو');
            });
        }
        
        checkConnection();
        // Check connection every 5 minutes
        setInterval(checkConnection, 300000);
    });
    </script>
    <?php
}

// Add connection status to both admin pages
function uvp_add_connection_status_to_pages() {
    $current_screen = get_current_screen();
    if ($current_screen->base === 'toplevel_page_borrzu-secret-key' || 
        $current_screen->base === 'برزو_page_borrzu-api-logs') {
        uvp_add_connection_status();
    }
}
add_action('admin_footer', 'uvp_add_connection_status_to_pages');

// Add new endpoints for user verification and purchase status
function uvp_register_api_endpoints() {
    // Existing verification endpoint
    register_rest_route('borrzu/v1', '/verify', array(
        'methods' => 'GET',
        'callback' => 'uvp_verify_plugin',
        'permission_callback' => '__return_true'
    ));

    // New endpoint for user verification
    register_rest_route('borrzu/v1', '/verify-user', array(
        'methods' => 'POST',
        'callback' => 'uvp_verify_user',
        'permission_callback' => function(WP_REST_Request $request) {
            // Check if it seems like a JWT token is being used
            $auth_header = $request->get_header('authorization');
            if (!empty($auth_header) && preg_match('/Bearer\s+(.*)$/i', $auth_header, $matches)) {
                $token = trim($matches[1]);
                if (substr_count($token, '.') == 2) {
                    // This is likely a JWT token, so show a helpful message
                    $error = new WP_Error(
                        'borrzu_jwt_conflict', 
                        'JWT token detected - برای استفاده از API برزو، لطفا از هدر X-Borrzu-Auth استفاده کنید', 
                        array('status' => 403)
                    );
                    
                    // Register a filter to modify the response
                    add_filter('rest_request_before_callbacks', function($response) use ($error) {
                        if (is_wp_error($response)) {
                            return $response;
                        }
                        return $error;
                    });
                    
                    return false;
                }
            }
            
            return uvp_verify_api_key();
        },
        'args' => array(
            'email' => array(
                'required' => true,
                'type' => 'string',
                'format' => 'email',
                'description' => 'User email address'
            ),
            'username' => array(
                'required' => false,
                'type' => 'string',
                'description' => 'Username (optional)'
            )
        )
    ));

    // New endpoint for purchase verification
    register_rest_route('borrzu/v1', '/verify-purchase', array(
        'methods' => 'POST',
        'callback' => 'uvp_verify_purchase',
        'permission_callback' => function(WP_REST_Request $request) {
            // Check if it seems like a JWT token is being used
            $auth_header = $request->get_header('authorization');
            if (!empty($auth_header) && preg_match('/Bearer\s+(.*)$/i', $auth_header, $matches)) {
                $token = trim($matches[1]);
                if (substr_count($token, '.') == 2) {
                    // This is likely a JWT token, so show a helpful message
                    $error = new WP_Error(
                        'borrzu_jwt_conflict', 
                        'JWT token detected - برای استفاده از API برزو، لطفا از هدر X-Borrzu-Auth استفاده کنید', 
                        array('status' => 403)
                    );
                    
                    // Register a filter to modify the response
                    add_filter('rest_request_before_callbacks', function($response) use ($error) {
                        if (is_wp_error($response)) {
                            return $response;
                        }
                        return $error;
                    });
                    
                    return false;
                }
            }
            
            return uvp_verify_api_key();
        },
        'args' => array(
            'email' => array(
                'required' => true,
                'type' => 'string',
                'format' => 'email',
                'description' => 'User email address'
            ),
            'product_id' => array(
                'required' => true,
                'type' => 'integer',
                'description' => 'Product ID to verify'
            )
        )
    ));
}
add_action('rest_api_init', 'uvp_register_api_endpoints');

// Verify API key from request headers
function uvp_verify_api_key() {
    // Check for our custom header first (preferred method)
    $borrzu_header = $_SERVER['HTTP_X_BORRZU_AUTH'] ?? '';
    if (!empty($borrzu_header)) {
        $secret_key = trim($borrzu_header);
    } else {
        // Fallback to Authorization header, but try to avoid conflict with JWT plugin
        $auth_header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (!preg_match('/Bearer\s+(.*)$/i', $auth_header, $matches)) {
            return false;
        }
        
        $secret_key = trim($matches[1]);
        
        // Check if this might be a JWT token (JWTs have 3 segments separated by dots)
        if (substr_count($secret_key, '.') == 2) {
            return false; // Let JWT plugin handle this
        }
    }
    
    global $wpdb;
    
    // Check if the key exists in user meta
    $user_with_key = $wpdb->get_var($wpdb->prepare(
        "SELECT user_id FROM {$wpdb->usermeta} WHERE meta_key = 'uvp_secret_key' AND meta_value = %s",
        $secret_key
    ));

    return !empty($user_with_key);
}

// User verification endpoint callback
function uvp_verify_user(WP_REST_Request $request) {
    $email = sanitize_email($request->get_param('email'));
    $username = sanitize_user($request->get_param('username'));

    // Check if user exists by email
    $user = get_user_by('email', $email);
    
    // If not found by email and username is provided, try by username
    if (!$user && $username) {
        $user = get_user_by('login', $username);
    }

    if (!$user) {
        $response = array(
            'exists' => false,
            'message' => 'کاربر یافت نشد'
        );
        $status_code = 404;
    } else {
        $response = array(
            'exists' => true,
            'message' => 'کاربر یافت شد',
            'user_data' => array(
                'id' => $user->ID,
                'email' => $user->user_email,
                'username' => $user->user_login,
                'registered_date' => $user->user_registered
            )
        );
        $status_code = 200;
    }

    // Log the API call
    uvp_log_api_call(
        get_current_user_id(),
        'verify-user',
        $request->get_headers(),
        array('email' => $email, 'username' => $username),
        $response,
        $status_code
    );

    return new WP_REST_Response($response, $status_code);
}

// Purchase verification endpoint callback
function uvp_verify_purchase(WP_REST_Request $request) {
    $email = sanitize_email($request->get_param('email'));
    $product_id = intval($request->get_param('product_id'));

    // Get user by email
    $user = get_user_by('email', $email);
    
    if (!$user) {
        $response = array(
            'has_purchased' => false,
            'message' => 'کاربر یافت نشد'
        );
        $status_code = 404;
    } else {
        // Check if WooCommerce is active
        if (class_exists('WooCommerce')) {
            $has_purchased = wc_customer_bought_product($user->user_email, $user->ID, $product_id);
            $response = array(
                'has_purchased' => $has_purchased,
                'message' => $has_purchased ? 'کاربر این محصول را خریداری کرده است' : 'کاربر این محصول را خریداری نکرده است',
                'user_id' => $user->ID,
                'product_id' => $product_id
            );
            $status_code = 200;
        } else {
            $response = array(
                'error' => true,
                'message' => 'ووکامرس فعال نیست'
            );
            $status_code = 500;
        }
    }

    // Log the API call
    uvp_log_api_call(
        get_current_user_id(),
        'verify-purchase',
        $request->get_headers(),
        array('email' => $email, 'product_id' => $product_id),
        $response,
        $status_code
    );

    return new WP_REST_Response($response, $status_code);
}