<?php
namespace dhflagging\AzureAuth;
use Illuminate\Support\ServiceProvider;
use dhflagging\AzureAuth\Http\Middleware\AzureAuth;
use Illuminate\Contracts\Http\Kernel;

class AzureAuthServiceProvider extends ServiceProvider
{
    public function boot() : void
    {
        $kernel = $this->app->make(Kernel::class);
        $kernel->pushMiddleware(AzureAuth::class);    
    }

    public function register() : void
    {

    }
}