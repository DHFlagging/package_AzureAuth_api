<?php

namespace dhflagging\AzureAuth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use TheNetworg\OAuth2\Client\Provider\Azure;
use Laravel\Socialite\Facades\Socialite;

class AzureAuth
{
    private Azure $provider;
    private array $ignore_routes = ['auth/redirect','auth/callback'];
    private string $user_oid = '';
    private string $email = '';
    private array $user = [];
    function __construct()
    {
        $this->provider = new Azure([
            'clientId'          => config('azureauth.azureClientID'),
            'clientSecret'      => config('azureauth.azureClientSecret'),
            'redirectUri'       => config('azureauth.azureRedirectUri')
        ]);
        ForEach(config('azureauth.disable_auth',[]) as $route_string)
        {
            $this->ignore_routes[] = $route_string;
        }
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
        config(['services.azure.redirect' => url()->current()]);
        if($this->ignoreRoute($request) === false)
        {
            try {
                $this->validateAuthHeader($request);
                $this->setEmail($request);
                $this->setOid($request);
            }catch(\Exception $e)
            {
                return Socialite::driver('azure')->stateless()->redirect();
            }
        }
        return $next($request);
    }

    private function ignoreRoute(Request $request) : bool
    {
        $regex = '#' . implode('|', $this->ignore_routes) . '#';
        if (preg_match($regex, $request->path()) === 1) {
            return true;
        }
        return false;
    }

    private function validateAuthHeader(Request $request) : bool
    {
        if($this->deviceAuthorizing($request)) {
            if ($this->validDevice($request))
            {
                return true;
            }
            throw new \Exception('no user present or invalid device');
        }else
        {
            $this->validateUser($request);
            return true;
        }
    }

    private function deviceAuthorizing(Request $request) : bool
    {
        if(str_starts_with($request->header('Authorization',false),'Bearer '))
        {
            return true;
        }
        return false;
    }

    private function validDevice(Request $request) : bool
    {
        return in_array(substr($request->header('Authorization'),7),config('azureauth.authorized_devices'));
    }

    private function validateUser(Request $request) : void
    {
        try {
            $this->user = $this->provider->validateAccessToken($request->header('Authorization'));
        }catch(\Exception $e)
        {
            $user = Socialite::driver('azure')->stateless()->user();
            $this->user = ['upn' => $user->getEmail(),'oid' => $user->getId()];
        }
    }

    private function getToken(Request $request) : array
    {
        return $this->user;
    }

    private function setEmail(Request $request) : void
    {
        if($this->deviceAuthorizing($request))
        {
            $this->email = config('azureauth.system_user_email');
        }else
        {
            $token = $this->getToken($request);
            $this->email = $token['upn'];
        }
    }

    private function setOid(Request $request) : void
    {
        if($this->deviceAuthorizing($request))
        {
            $this->user_oid = (string) $request->header('User',config('azureauth.system_user_oid'));
        }else
        {
            $token = $this->getToken($request);
            $this->email = $token['oid'];
        }
    }

    public function Get_User_Oid(Request $request) : string
    {
        return $this->user_oid;
    }

    public function Get_User_Email(Request $request) : string
    {
        return $this->email;
    }

}
