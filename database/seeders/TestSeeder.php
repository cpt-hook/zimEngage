<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;

class TestSeeder extends Seeder
{
    public function run()
    {
        // This will output the actual connection being used
        dump('Current connection: ' . DB::connection()->getName());
        
        // Simple insert to test if MySQL is working
        DB::table('settings')->insert([
            'key' => 'test_key',
            'value' => 'test_value',
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }
} 