# Borrzu WordPress Plugin

![Borrzu Logo](assets/logo.svg)

A powerful WordPress plugin for managing API keys and monitoring API requests for Borrzu.com integration.

[🇮🇷 مستندات فارسی](README-fa.md)


## 🚀 Features

- **Secure Key Management**: Generate and manage secret API keys for users
- **API Request Monitoring**: Track and monitor all API requests with detailed logs
- **Advanced Filtering**: Filter API logs by endpoint, status, and date range
- **User Verification**: Verify user accounts and purchases through secure API endpoints
- **WooCommerce Integration**: Seamlessly verify product purchases
- **Persian Language Support**: Full RTL support with Persian interface

## 📸 Screenshots

### API Logs Dashboard
![API Logs Dashboard](assets/1.png)
*Monitor and filter API requests with detailed information*

### Key Management
![Key Management](assets/2.png)
*Securely manage API keys with regeneration capability*

### Detailed Request Logs
![Request Details](assets/3.png)
*View detailed request and response information in a clean modal interface*

## 🔧 Installation

1. Download the plugin zip file
2. Go to WordPress admin panel > Plugins > Add New
3. Click "Upload Plugin" and select the downloaded zip file
4. Click "Install Now" and then "Activate"

## ⚙️ Requirements

- WordPress 5.0 or higher
- PHP 7.4 or higher
- SSL Certificate (HTTPS) required
- WooCommerce (optional, for purchase verification)

## 🔒 Security Features

- Secure key generation using WordPress cryptographic functions
- Rate limiting for API key generation
- Nonce verification for all admin actions
- Data sanitization and validation
- SSL requirement enforcement

## 🛠️ API Endpoints

The plugin provides several REST API endpoints:

### Verify User
```http
POST /wp-json/borrzu/v1/verify-user
```
Parameters:
- `email` (required): User email address
- `username` (optional): Username

### Verify Purchase
```http
POST /wp-json/borrzu/v1/verify-purchase
```
Parameters:
- `email` (required): User email address
- `product_id` (required): WooCommerce product ID

## 📝 Usage

### Authentication
All API requests must include your secret key in the Authorization header:
```http
Authorization: Bearer YOUR_SECRET_KEY
```

### Example Request
```php
$response = wp_remote_post('https://your-site.com/wp-json/borrzu/v1/verify-user', [
    'headers' => [
        'Authorization' => 'Bearer ' . $secret_key,
        'Content-Type' => 'application/json'
    ],
    'body' => json_encode([
        'email' => 'user@example.com'
    ])
]);
```

## 🔐 Security Best Practices

- Regenerate keys periodically
- Never share your secret key
- Monitor API logs regularly
- Keep the plugin updated
- Maintain SSL certificate


---

Made with ❤️ by [Borrzu.com](https://borrzu.com)