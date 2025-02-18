<?php
/*
Plugin Name: User Verification Plugin
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
            <img src="https://borrzu-public.storage.c2.liara.space/assets/logo-white.svg" alt="Borrzu Logo" style="width: 24px; vertical-align: middle;">
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