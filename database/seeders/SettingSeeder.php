<?php

declare(strict_types=1);

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;

final class SettingSeeder extends Seeder
{
    public function run(): void
    {
        DB::table('settings')->insert([
            [
                'key' => 'site_name',
                'value' => 'GovVoice',
                'type' => 'string',
                'group' => 'general',
                'is_public' => true,
            ],
            [
                'key' => 'feedback_moderation',
                'value' => 'true',
                'type' => 'boolean',
                'group' => 'moderation',
                'is_public' => false,
            ],
            [
                'key' => 'allowed_file_types',
                'value' => json_encode(['pdf', 'doc', 'docx', 'jpg', 'png']),
                'type' => 'array',
                'group' => 'uploads',
                'is_public' => true,
            ],
        ]);
    }
} 