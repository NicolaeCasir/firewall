<?php

namespace Akaunting\Firewall\Middleware;

class Swear extends Base
{
    public function getPatterns()
    {
        $patterns = [];

        if (!$words = config('firewall.middleware.' . $this->middleware . '.words')) {
            return $patterns;
        }

        foreach ((array) $words as $word) {
            $patterns[] = '#\b' . $word . '\b#i';
        }

        return $patterns;
    }
}
