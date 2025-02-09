<?php

namespace Akaunting\Firewall\Middleware;

use Akaunting\Firewall\Events\AttackDetected;
use Akaunting\Firewall\Models\Log;
use Closure;
use Illuminate\Support\Facades\Redirect;
use Illuminate\Support\Facades\Response;


abstract class Base
{
    public $request = null;
    public $input = null;
    public $middleware = null;
    public $user_id = null;

    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $this->request = $request;

        if ($this->skip($request)) {
            return $next($request);
        }

        if ($this->check($this->getPatterns())) {
            return $this->respond(config('firewall.responses.block'));
        }


        return $next($request);
    }

    public function skip($request)
    {
        $this->prepare($request);

        if (!$this->isEnabled()) {
            return true;
        }

        if (!$this->isMethod()) {
            return true;
        }

        if ($this->isRoute()) {
            return true;
        }

        return false;
    }

    public function prepare($request)
    {
        $this->request = $request;
        $this->input = $request->input();
        $this->middleware = strtolower((new \ReflectionClass($this))->getShortName());
        $this->user_id = auth()->id() ?: 0;
    }

    public function isEnabled()
    {
        return config('firewall.enabled');
    }


    public function isMethod()
    {
        if (!$methods = config('firewall.middleware.' . $this->middleware . '.methods')) {
            return false;
        }

        if (in_array('all', $methods)) {
            return true;
        }

        return in_array(strtolower($this->request->method()), $methods);
    }

    public function isRoute()
    {
        if (!$routes = config('firewall.middleware.' . $this->middleware . '.routes')) {
            return false;
        }

        foreach ($routes['except'] as $ex) {
            if (!$this->request->is($ex)) {
                continue;
            }

            return true;
        }

        foreach ($routes['only'] as $on) {
            if ($this->request->is($on)) {
                continue;
            }

            return true;
        }

        return false;
    }


    public function getPatterns()
    {
        return config('firewall.middleware.' . $this->middleware . '.patterns', []);
    }

    public function check($patterns)
    {
        $log = null;

        foreach ($patterns as $pattern) {
            if (!$match = $this->match($pattern, $this->input, $this->request)) {
                continue;
            }

            $log = $this->log();

            event(new AttackDetected($log));

            break;
        }

        if ($log) {
            return true;
        }

        return false;
    }

    public function match($pattern, $input)
    {
        $result = false;

        if (!is_array($input) && !is_string($input)) {
            return false;
        }

        if (!is_array($input)) {
            return preg_match($pattern, $input);
        }

        foreach ($input as $key => $value) {
            if (is_array($value)) {
                if (!$result = $this->match($pattern, $value)) {
                    continue;
                }

                break;
            }

            if (!$result = preg_match($pattern, $value)) {
                continue;
            }

            break;
        }

        return $result;
    }

    public function log()
    {
        $log = Log::create([
            'ip' => null,
            'level' => 'medium',
            'middleware' => $this->middleware,
            'user_id' => $this->user_id,
            'url' => $this->request->fullUrl(),
            'referrer' => $this->request->server('HTTP_REFERER') ?: 'NULL',
            'request' => urldecode(http_build_query($this->input)),
        ]);

        return $log;
    }

    public function respond($response, $data = [])
    {
        if ($response['code'] == 200) {
            return '';
        }

        if ($view = $response['view']) {
            return Response::view($view, $data);
        }

        if ($redirect = $response['redirect']) {
            if (($this->middleware == 'ip') && $this->request->is($redirect)) {
                abort($response['code'], trans('firewall::responses.block.message'));
            }

            return Redirect::to($redirect);
        }

        if ($response['abort']) {
            abort($response['code'], trans('firewall::responses.block.message'));
        }

        return Response::make(trans('firewall::responses.block.message'), $response['code']);
    }
}
