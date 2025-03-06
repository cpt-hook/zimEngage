<?php

declare(strict_types=1);

namespace Database\Seeders;

use App\Models\Tag;
use Illuminate\Database\Seeder;

final class TagSeeder extends Seeder
{
    public function run(): void
    {
        $tags = [
            ['name' => 'Urgent', 'slug' => 'urgent'],
            ['name' => 'New Policy', 'slug' => 'new-policy'],
            ['name' => 'Under Review', 'slug' => 'under-review'],
            ['name' => 'Implementation', 'slug' => 'implementation'],
        ];

        foreach ($tags as $tag) {
            Tag::create($tag);
        }
    }
} 