<?php

declare(strict_types=1);

namespace Database\Seeders;

use App\Models\Department;
use App\Models\PolicyCategory;
use Illuminate\Database\Seeder;
use Illuminate\Support\Str;

final class PolicyCategorySeeder extends Seeder
{
    public function run(): void
    {
        $categories = [
            [
                'name' => 'Agriculture',
                'department_code' => 'AGR',
                'icon' => 'agriculture',
            ],
            [
                'name' => 'Education',
                'department_code' => 'EDU',
                'icon' => 'school',
            ],
            [
                'name' => 'Healthcare',
                'department_code' => 'HLT',
                'icon' => 'health',
            ],
        ];

        foreach ($categories as $category) {
            $department = Department::where('code', $category['department_code'])->first();
            
            if ($department) {
                PolicyCategory::create([
                    'name' => $category['name'],
                    'slug' => Str::slug($category['name']),
                    'department_id' => $department->id,
                    'icon' => $category['icon'],
                ]);
            }
        }
    }
} 