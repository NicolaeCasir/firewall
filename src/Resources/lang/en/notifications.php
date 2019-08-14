<?php

return [

    'mail' => [

        'subject' => '🔥 Possible attack on :domain',
        'message' => 'A possible :middleware attack on :domain has been detected. The following URL has been affected: :url',

    ],

    'slack' => [

        'message' => 'A possible attack on :domain has been detected.',

    ],

];
