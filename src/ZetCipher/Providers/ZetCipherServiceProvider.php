<?php

namespace ZetCipher\Providers;

use Illuminate\Support\ServiceProvider;
use ZetCipher\Commands\EncryptTokenCommand;

class ZetCipherServiceProvider extends ServiceProvider
{
    public function boot()
    {
        if ($this->app->runningInConsole()) {
            $this->commands([
                EncryptTokenCommand::class,
            ]);
        }
    }
}