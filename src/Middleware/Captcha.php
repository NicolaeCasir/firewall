<?php

namespace Akaunting\Firewall\Middleware;

use Closure;
use Illuminate\Support\Str;

class Captcha extends Base
{
    public function handle($request, Closure $next)
    {
        /**
         *  Check config if captcha is Enabled
         */
        if (! (bool) config('firewall.middleware.captcha.enabled', true)) {
            return $next($request);
        }

        if (! Str::contains($request->path(), ['captcha', 'admin', 'settings'])) {

            /**
             *  Reflash session in order to keep data
             */
            $request->session()->reflash();

            if (blank(session('captcha_DDOS'))) {
                session(['captcha_DDOS' => $hash]);
                session()->save();
                return $next($request);
            }

            $uri = md5($request->fullUrl());
            $expire = 1; // 0 seconds
            $hash = $uri . '|' . time();

            $expired = explode('|', session('captcha_DDOS'));
            if ($expired[0] === $uri && time() - (int) $expired[1] < $expire) {
                if (! auth()->guest()) {
                    auth()->logout();
                }
                session()->forget('captcha_DDOS');
                cookie()->forget('XSRF-TOKEN');
                cookie()->forget('laravel_session');
                cookie()->forget('captcha_ddos');
                session()->put('captcha_DDOS', $hash);
                session()->save();

                header('HTTP/1.1 503 Service Unavailable');
                die('<h1>HTTP/1.1 503 Service Unavailable</h1><a type="button" href="/">Return to homepage</a>');
            }

            /**
             *  Save request data
             */
            session()->put('captcha_DDOS', $hash);
            session()->save();
        }

        if ($request->path() !== 'cheer' && $request->path() !== 'captcha/ddos') {

            /**
             *  Regenerate session data otherwise flush it
             */
            session()->regenerate();
            $cookie = $request->cookie('captcha_ddos');

            if ($cookie === "passed") {
                return $next($request);
            } else {
                return redirect()->to('/captcha');
            }
        }

        return $next($request);
    }
}
