<?php

namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;

class UserSeeder extends Seeder
{
    public function run(): void
    {
        // Verificar se os usuários já existem para evitar duplicatas
        if (!User::where('email', 'admin@test.com')->exists()) {
            User::create([
                'name' => 'Admin Demo',
                'email' => 'admin@test.com',
                'password' => Hash::make('password'),
            ]);
        }

        if (!User::where('email', 'joao@test.com')->exists()) {
            User::create([
                'name' => 'João Silva',
                'email' => 'joao@test.com',
                'password' => Hash::make('password'),
            ]);
        }

        if (!User::where('email', 'maria@test.com')->exists()) {
            User::create([
                'name' => 'Maria Santos',
                'email' => 'maria@test.com',
                'password' => Hash::make('password'),
            ]);
        }
    }
}