# Web Application Firewall (WAF) package for Laravel

[![Version](https://poser.pugx.org/akaunting/firewall/v/stable.svg)](https://github.com/akaunting/firewall/releases)
![Downloads](https://poser.pugx.org/akaunting/firewall/d/total.svg)
![Build Status](https://travis-ci.com/akaunting/firewall.svg)
[![StyleCI](https://styleci.io/repos/197242392/shield?style=flat&branch=master)](https://styleci.io/repos/197242392)
[![Quality](https://scrutinizer-ci.com/g/akaunting/firewall/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/akaunting/firewall)
[![License](https://poser.pugx.org/akaunting/firewall/license.svg)](LICENSE.md)

This package intends to protect your Laravel app from different type of attacks such as XSS, SQLi, RFI, LFI, User Agent, and a lot more. It will also block repeated attacks and send notification via email and/or slack when attack is detected. Furthermore, it will log failed logins and block the IP after a number of attempts.

Note: Some middleware classes (i.e. Xss) are empty as the `Base` class that they extend does all of the job, dynamically. In short, they all works ;)

## Getting Started

### 1. Install

Run the following command:

```bash
composer require akaunting/firewall
```

### 2. Register (for Laravel < 5.5)

Register the service provider in `config/app.php`

```php
Akaunting\Firewall\Provider::class,
```

### 3. Publish

Publish configuration, language, and migrations

```bash
php artisan vendor:publish --tag=firewall
```

### 4. Database

Create db tables

```bash
php artisan migrate
```

### 5. Configure

You can change the firewall settings of your app from `config/firewall.php` file

## Usage

Middlewares are already defined so should just add them to routes. The `firewall.all` middleware applies all the middlewares available in the `all_middleware` array of config file. 

```php
Route::group(['middleware' => 'firewall.all'], function () {
    Route::get('/', 'HomeController@index');
});
```

You can apply each middleware per route. For example, you can allow only whitelisted IPs to access admin:

```php
Route::group(['middleware' => 'firewall.whitelist'], function () {
    Route::get('/admin', 'AdminController@index');
});
```

Or you can get notified when anyone NOT in `whitelist` access admin, by adding it to the `inspections` config:

```php
Route::group(['middleware' => 'firewall.url'], function () {
    Route::get('/admin', 'AdminController@index');
});
```

Available middlewares applicable to routes:

```php
firewall.all

firewall.agent
firewall.geo
firewall.ip
firewall.lfi
firewall.php
firewall.referrer
firewall.rfi
firewall.session
firewall.sqli
firewall.swear
firewall.url
firewall.whitelist
firewall.xss
```

You may also define `routes` for each middleware in `config/firewall.php` and apply that middleware or `firewall.all` at the top of all routes.

## Notifications

Firewall will send a notification as soon as an attack has been detected. Emails entered in `notifications.email.to` config must be valid Laravel users in order to send notifications. Check out the Notifications documentation of Laravel for further information.

## Changelog

Please see [Releases](../../releases) for more information what has changed recently.

## Contributing

Pull requests are more than welcome.

## Security

If you discover any security related issues, please email security@akaunting.com instead of using the issue tracker.

## Credits

- [Denis Duliçi](https://github.com/denisdulici)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [LICENSE](LICENSE.md) for more information.
