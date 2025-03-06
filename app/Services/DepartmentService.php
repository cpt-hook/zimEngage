<?php

declare(strict_types=1);

namespace App\Services;

use App\Models\Department;

final readonly class DepartmentService
{
    public function create(array $data): Department
    {
        return Department::create($data);
    }

    public function update(Department $department, array $data): Department
    {
        $department->update($data);
        return $department->refresh();
    }

    public function delete(Department $department): void
    {
        $department->delete();
    }
} 

