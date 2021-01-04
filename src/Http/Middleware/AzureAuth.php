<?php

namespace dhflagging\AzureAuth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use TheNetworg\OAuth2\Client\Provider\Azure;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
class AzureAuth
{
    private Azure $provider;
    function __construct()
    {
        $this->provider = new Azure([
            'clientId'          => env('azureClientID'),
            'clientSecret'      => env('azureClientSecret'),
            'redirectUri'       => env('azureRedirectUri')
        ]);        
    }
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        try
        {
            $token = $this->provider->validateAccessToken($request->header('Authorization'));
        }catch(\Exception $e)
        {
            return response()->json(["message" => "Unauthorized","dev_details" => $e->getMessage()],401);
        }
        return $next($request);
    }

    public function Get_User_Oid(Request $request) : string
    {
        $token = $this->provider->validateAccessToken($request->header('Authorization'));
        return $token['oid'];
    }
    
    public function Get_User_Email(Request $request) : string
    {
        $token = $this->provider->validateAccessToken($request->header('Authorization'));
        return $token['upn'];

    }

}
