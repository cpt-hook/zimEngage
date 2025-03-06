<?php

declare(strict_types=1);

namespace Database\Seeders;

use App\Models\Department;
use Illuminate\Database\Seeder;

final class DepartmentSeeder extends Seeder
{
    public function run(): void
    {
        $departments = [
            [
                'name' => 'Ministry of Agriculture',
                'code' => 'AGR',
                'description' => 'Responsible for agricultural policies and food security',
                'is_active' => true,
            ],
            [
                'name' => 'Ministry of Education',
                'code' => 'EDU',
                'description' => 'Responsible for education policies and curriculum development',
                'is_active' => true,
            ],
            [
                'name' => 'Ministry of Health',
                'code' => 'HLT',
                'description' => 'Responsible for healthcare policies and public health',
                'is_active' => true,
            ],
        ];

        foreach ($departments as $dept) {
            Department::create($dept);
        }
    }
} 