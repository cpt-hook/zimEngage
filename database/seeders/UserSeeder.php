<?php

declare(strict_types=1);

namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;

final class UserSeeder extends Seeder
{
    public function run(): void
    {
        // Create admin user
        $admin = User::create([
            'national_id' => '63-123456-A-42',
            'name' => 'Admin User',
            'email' => 'admin@govvoice.co.zw',
            'password' => Hash::make('admin123'),
            'role' => 'admin',
            'province' => 'Harare',
        ]);

        // Create test user
        User::create([
            'national_id' => '63-345678-C-42',
            'name' => 'thamu ncube',
            'email' => 'thamu@gmail.com.com',
            'password' => Hash::make('user123'),
            'role' => 'user',
            'province' => 'Manicaland',
        ]);
    }
} 