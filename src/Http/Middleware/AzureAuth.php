<?php

namespace jbirch8865\AzureAuth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class AzureAuth
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        $provider = new \TheNetworg\OAuth2\Client\Provider\Azure([
            'clientId'          => env('azureClientID'),
            'clientSecret'      => env('azureClientSecret'),
            'redirectUri'       => env('azureRedirectUri')
        ]);
        try
        {
            $token = $provider->validateAccessToken($request->header('Authorization'));
        }catch(\Exception $e)
        {
            return response()->json(["message" => "Unauthorized","dev_details" => $e->getMessage()],401);
        }
        return $next($request);
    }
}
