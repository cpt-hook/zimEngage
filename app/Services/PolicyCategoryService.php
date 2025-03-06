<?php
declare(strict_types=1);

namespace App\Services;

use App\Models\PolicyCategory;
use Illuminate\Support\Str;

final readonly class PolicyCategoryService
{
    public function create(array $data): PolicyCategory
    {
        return PolicyCategory::create([
            ...$data,
            'slug' => Str::slug($data['name']),
        ]);
    }

    public function update(PolicyCategory $category, array $data): PolicyCategory
    {
        $category->update([
            ...$data,
            'slug' => isset($data['name']) ? Str::slug($data['name']) : $category->slug,
        ]);

        return $category->refresh();
    }

    public function delete(PolicyCategory $category): void
    {
        $category->delete();
    }
} 