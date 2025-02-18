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

// Function to log API calls
function uvp_log_api_call($user_id, $endpoint, $headers, $request_data, $response_data, $status_code) {
    global $wpdb;
    $table_name = $wpdb->prefix . 'borrzu_api_logs';
    
    $wpdb->insert(
        $table_name,
        array(
            'user_id' => $user_id,
            'endpoint' => $endpoint,
            'headers' => json_encode($headers),
            'request_data' => json_encode($request_data),
            'response_data' => json_encode($response_data),
            'status_code' => $status_code
        ),
        array('%d', '%s', '%s', '%s', '%s', '%d')
    );
}

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

// API Logs page
function uvp_api_logs_page() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'borrzu_api_logs';
    
    // Pagination
    $per_page = 20;
    $current_page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
    $offset = ($current_page - 1) * $per_page;
    
    // Get logs
    $logs = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT * FROM $table_name WHERE user_id = %d ORDER BY created_at DESC LIMIT %d OFFSET %d",
            get_current_user_id(),
            $per_page,
            $offset
        )
    );
    
    $total_items = $wpdb->get_var(
        $wpdb->prepare(
            "SELECT COUNT(*) FROM $table_name WHERE user_id = %d",
            get_current_user_id()
        )
    );
    
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

        <div class="borrzu-card">
            <?php if (empty($logs)) : ?>
                <div class="borrzu-empty-state">
                    <img src="<?php echo plugins_url('assets/empty-state.svg', __FILE__); ?>" alt="بدون گزارش">
                    <p>هنوز هیچ درخواست API‌ای ثبت نشده است.</p>
                </div>
            <?php else : ?>
                <div class="borrzu-logs-table">
                    <?php foreach ($logs as $log) : ?>
                        <div class="log-item <?php echo $log->status_code >= 200 && $log->status_code < 300 ? 'success' : 'error'; ?>">
                            <div class="log-header">
                                <span class="endpoint"><?php echo esc_html($log->endpoint); ?></span>
                                <span class="status-code"><?php echo esc_html($log->status_code); ?></span>
                                <span class="date"><?php echo wp_date('Y/m/d H:i', strtotime($log->created_at)); ?></span>
                            </div>
                            <div class="log-details" style="display: none;">
                                <div class="detail-section">
                                    <h4>هدرها:</h4>
                                    <pre><?php echo esc_html(json_encode(json_decode($log->headers), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)); ?></pre>
                                </div>
                                <div class="detail-section">
                                    <h4>داده‌های درخواست:</h4>
                                    <pre><?php echo esc_html(json_encode(json_decode($log->request_data), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)); ?></pre>
                                </div>
                                <div class="detail-section">
                                    <h4>پاسخ:</h4>
                                    <pre><?php echo esc_html(json_encode(json_decode($log->response_data), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)); ?></pre>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
                
                <?php
                $total_pages = ceil($total_items / $per_page);
                if ($total_pages > 1) :
                ?>
                <div class="borrzu-pagination">
                    <?php
                    echo paginate_links(array(
                        'base' => add_query_arg('paged', '%#%'),
                        'format' => '',
                        'prev_text' => __('&laquo;'),
                        'next_text' => __('&raquo;'),
                        'total' => $total_pages,
                        'current' => $current_page
                    ));
                    ?>
                </div>
                <?php endif; ?>
            <?php endif; ?>
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
            padding: 40px 20px;
        }
        .borrzu-empty-state img {
            width: 150px;
            margin-bottom: 20px;
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
        .log-item.error .log-header {
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
    </style>

    <script>
    jQuery(document).ready(function($) {
        $('.log-header').click(function() {
            $(this).next('.log-details').slideToggle();
        });
    });
    </script>
    <?php
}

// محتوای صفحه مدیریت
function uvp_admin_page() {
    $user_id = get_current_user_id();
    $secret_key = get_user_meta($user_id, 'uvp_secret_key', true);
    
    // Get current tab
    $current_tab = isset($_GET['tab']) ? sanitize_text_field($_GET['tab']) : 'manage-keys';

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
            <a href="?page=borrzu-secret-key" class="tab-item">مدیریت کلید‌ها</a>
            <a href="?page=borrzu-api-logs" class="tab-item">گزارش‌های API</a>
        </div>

        <div class="borrzu-card">
            <div class="borrzu-inner-tabs">
                <a href="?page=borrzu-secret-key&tab=manage-keys" 
                   class="inner-tab-item <?php echo $current_tab === 'manage-keys' ? 'active' : ''; ?>">
                    <span class="dashicons dashicons-admin-network"></span>
                    مدیریت کلید
                </a>
                <a href="?page=borrzu-secret-key&tab=documentation" 
                   class="inner-tab-item <?php echo $current_tab === 'documentation' ? 'active' : ''; ?>">
                    <span class="dashicons dashicons-book"></span>
                    راهنمای استفاده
                </a>
            </div>

            <?php if ($current_tab === 'manage-keys'): ?>
                <div class="tab-content">
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
            <?php elseif ($current_tab === 'documentation'): ?>
                <div class="tab-content">
                    <div class="documentation-section">
                        <h2>راهنمای استفاده از API برزو</h2>
                        
                        <div class="doc-section">
                            <h3>نحوه استفاده از کلید مخفی</h3>
                            <p>برای استفاده از API برزو، باید کلید مخفی خود را در هدر درخواست‌ها قرار دهید:</p>
                            <pre><code>Authorization: Bearer YOUR_SECRET_KEY</code></pre>
                        </div>

                        <div class="doc-section">
                            <h3>نمونه کد</h3>
                            <div class="code-example">
                                <div class="code-tabs">
                                    <button class="code-tab active" data-lang="curl">cURL</button>
                                    <button class="code-tab" data-lang="php">PHP</button>
                                    <button class="code-tab" data-lang="js">JavaScript</button>
                                </div>
                                <div class="code-content curl active">
                                    <pre><code>curl -X POST "https://api.borrzu.com/v1/endpoint" \
-H "Authorization: Bearer YOUR_SECRET_KEY" \
-H "Content-Type: application/json" \
-d '{"key": "value"}'</code></pre>
                                </div>
                                <div class="code-content php">
                                    <pre><code>$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "https://api.borrzu.com/v1/endpoint");
curl_setopt($ch, CURLOPT_HTTPHEADER, array(
    "Authorization: Bearer " . YOUR_SECRET_KEY,
    "Content-Type: application/json"
));
$result = curl_exec($ch);</code></pre>
                                </div>
                                <div class="code-content js">
                                    <pre><code>fetch('https://api.borrzu.com/v1/endpoint', {
    method: 'POST',
    headers: {
        'Authorization': `Bearer ${YOUR_SECRET_KEY}`,
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({ key: 'value' })
});</code></pre>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endif; ?>
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
        
        /* Documentation styles */
        .documentation-section {
            max-width: 800px;
            margin: 0 auto;
        }
        .doc-section {
            margin-bottom: 30px;
        }
        .doc-section h3 {
            color: #2271b1;
            margin-bottom: 15px;
        }
        .code-example {
            background: #f8f9fa;
            border-radius: 8px;
            overflow: hidden;
        }
        .code-tabs {
            background: #fff;
            border-bottom: 1px solid #ddd;
            padding: 10px;
        }
        .code-tab {
            background: none;
            border: none;
            padding: 8px 16px;
            cursor: pointer;
            margin-left: 10px;
            border-radius: 4px;
        }
        .code-tab.active {
            background: #2271b1;
            color: white;
        }
        .code-content {
            display: none;
            padding: 20px;
        }
        .code-content.active {
            display: block;
        }
        pre {
            margin: 0;
            white-space: pre-wrap;
            direction: ltr;
            text-align: left;
        }
        code {
            font-family: monospace;
            font-size: 14px;
        }
    </style>

    <script>
    jQuery(document).ready(function($) {
        // Existing scripts ...

        // Code tabs functionality
        $('.code-tab').click(function() {
            const lang = $(this).data('lang');
            $('.code-tab').removeClass('active');
            $(this).addClass('active');
            $('.code-content').removeClass('active');
            $(`.code-content.${lang}`).addClass('active');
        });
    });
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

// Verification endpoint callback
function uvp_verify_plugin(WP_REST_Request $request) {
    $site_url = get_site_url();
    $plugin_version = '1.0'; // Match your plugin version
    $user_count = count_users();
    
    // Get plugin status
    $is_active = is_plugin_active(plugin_basename(__FILE__));
    
    // Get connection status - check if any user has a secret key
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
        'connection_status' => array(
            'connected' => true,
            'message' => 'اتصال به برزو برقرار است'
        )
    );

    // Log this verification check
    if (function_exists('uvp_log_api_call')) {
        uvp_log_api_call(
            0, // system check, no specific user
            'verify',
            array('source' => 'borrzu.com'),
            array('site_url' => $site_url),
            $response,
            200
        );
    }

    return new WP_REST_Response($response, 200);
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