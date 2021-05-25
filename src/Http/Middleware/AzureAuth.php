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
            'clientId'          => env('azureClientID'),
            'clientSecret'      => env('azureClientSecret'),
            'redirectUri'       => env('azureRedirectUri')
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
                $this->validAuthHeader($request);
                $this->setEmail($request);
                $this->setOid($request);
            }catch(\Exception $e)
            {
                return response()->json(['message' => 'unauthorized']);
            }
        }
        return $next($request);
    }

    public function Get_User_Oid(Request $request) : string
    {
        return $this->user_oid;
    }

    public function Get_User_Email(Request $request) : string
    {
        return $this->email;
    }

    private function validAuthHeader(Request $request) : bool
    {
        if($this->deviceAuthorizing($request)) {
            if ($this->userHeaderPresent($request))
            {
                return true;
            }
            throw new \Exception('no user present');
        }else
        {
            $this->getToken($request);
            return true;
        }
    }

    private function setEmail(Request $request) : void
    {
        if($this->deviceAuthorizing($request))
        {
            $this->email = 'support@d-hflagging.com';
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

    private function ignoreRoute(Request $request) : bool
    {
        $regex = '#' . implode('|', $this->ignore_routes) . '#';
        if (preg_match($regex, $request->path()) !== 0) {
            return true;
        }
        return false;
    }

    private function getToken(Request $request) : array
    {
        return $this->provider->validateAccessToken($request->header('Authorization'));
    }
}
