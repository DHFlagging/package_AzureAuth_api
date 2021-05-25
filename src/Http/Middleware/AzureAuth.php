<?php

namespace dhflagging\AzureAuth\Http\Middleware;

use App\Http\Middleware\PreventRequestsDuringMaintenance;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use TheNetworg\OAuth2\Client\Provider\Azure;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
class AzureAuth
{
    private Azure $provider;
    private array $ignore_routes = ['auth/redirect','auth/callback'];
    private string $user_oid = '';
    private string $email = '';
    function __construct()
    {
        $this->provider = new Azure([
            'clientId'          => config('azureauth.azureClientID'),
            'clientSecret'      => config('azureauth.azureClientSecret'),
            'redirectUri'       => config('azureauth.azureRedirectUri')
        ]);
        ForEach(config('app.disable_auth',[]) as $route_string)
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
        if($this->ignoreRoute($request) === false)
        {
            try {
                $this->validateAuthHeader($request);
                $this->setEmail($request);
                $this->setOid($request);
            }catch(\Exception $e)
            {
                return response()->json(['message' => 'unauthorized']);
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
            if ($this->userHeaderPresent($request) && $this->validDevice($request))
            {
                return true;
            }
            throw new \Exception('no user present or invalid device');
        }else
        {
            $this->getToken($request);
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

    private function userHeaderPresent(Request $request) : bool
    {
        if($request->header('User',false) && is_string($request->header('User')) === true)
        {
            return true;
        }
        return false;
    }

    private function getToken(Request $request) : array
    {
        return $this->provider->validateAccessToken($request->header('Authorization'));
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
            $this->user_oid = (string) $request->header('User','');
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
