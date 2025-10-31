<?php

namespace ZetCipher\Commands;

use Illuminate\Console\Command;
use ZetCipher\Foundation\Foundation;

class EncryptTokenCommand extends Command
{
    protected $signature = 'zetcipher:key';
    protected $description = 'Set the zetcipher key';

    public function handle()
    {
        $this->line('<fg=magenta;options=bold>[ ZETCIPHER v1.0 ]</> - Cryptography for secure token and verification');
        $this->line('<fg=gray>(c) 2025 by Anonputraid</>');
        $this->newLine();

        $code    = getZetCipherSecurityCode();
        $id      = getZetCipherID();
        $token   = getZetCipherToken();
        $pasport = random_int(1000000, 3618800);

        $this->line('<fg=yellow>ZETCIPHER_CIPHER=</>' . $code);
        $this->line('<fg=yellow>ZETCIPHER_ACCESS_KEY_ID=</>' . $id);
        $this->line('<fg=yellow>ZETCIPHER_ACCESS_KEY=</>' . $token);
        $this->line('<fg=yellow>ZETCIPHER_SIGNING_SECRET=</>' . $pasport);
        $this->line('<fg=yellow>ZETCIPHER_TOKEN_LIFETIME=</>3600');
        $this->newLine(2);

        Foundation::generate(fileName: "EncryptionResources.php", type: "private");
        Foundation::generate(fileName: "SystemResources.php", type: "system");
        Foundation::generate(fileName: "HideResources.php");

        $this->info('SUCCESS: Keys generated. Copy them to your .env file.');

        $this->line('<fg=red;options=bold>SECURITY WARNING:</>');
        $this->line('<fg=red>Treat these keys like a password and never share them. Changing them in production will invalidate all existing tokens.</>');

        $this->newLine();
    }
}