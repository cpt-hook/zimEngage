<?php

declare(strict_types=1);

namespace Database\Seeders;

use App\Models\FaqCategory;
use Illuminate\Database\Seeder;

final class FaqCategorySeeder extends Seeder
{
    public function run(): void
    {
        $categories = [
            ['name' => 'General Questions', 'slug' => 'general'],
            ['name' => 'Policy Feedback', 'slug' => 'feedback'],
            ['name' => 'Technical Support', 'slug' => 'support'],
        ];

        foreach ($categories as $category) {
            FaqCategory::create($category);
        }
    }
} 