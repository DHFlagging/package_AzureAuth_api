<?php
return [
    'system_user_oid' => env('system_user_oid','49b76f8f-6624-44db-860d-cb9442c9c121'),
    'system_user_email' => env('system_user_email','support@d-hflagging.com'),
    'azureRedirectUri' => env('azureRedirectUri'),
    'azureClientSecret' => env('azureClientSecret'),
    'azureClientID' => env('azureClientID'),
    'authorized_devices' => env('external_authorized_devices',[]),
    'disable_auth' => ['_debugbar','css','js','livewire']
];
