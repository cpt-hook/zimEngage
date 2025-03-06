<?php

declare(strict_types=1);

namespace App\Http\Controllers\API;

use App\Http\Requests\DepartmentStoreRequest;
use App\Http\Requests\DepartmentUpdateRequest;
use App\Http\Resources\DepartmentResource;
use App\Models\Department;
use App\Services\DepartmentService;

final class DepartmentController extends BaseController
{
    public function __construct(
        private readonly DepartmentService $departmentService
    ) {}

    public function index(): \Illuminate\Http\JsonResponse
    {
        $departments = Department::query()
            ->with('policyCategories')
            ->get();

        return $this->successResponse(
            DepartmentResource::collection($departments)
        );
    }

    public function store(DepartmentStoreRequest $request): \Illuminate\Http\JsonResponse
    {
        $department = $this->departmentService->create($request->validated());

        return $this->successResponse(
            data: new DepartmentResource($department),
            message: 'Department created successfully',
            status: 201
        );
    }

    public function show(Department $department): \Illuminate\Http\JsonResponse
    {
        return $this->successResponse(
            new DepartmentResource($department->load('policyCategories'))
        );
    }

    public function update(
        DepartmentUpdateRequest $request,
        Department $department
    ): \Illuminate\Http\JsonResponse {
        $updatedDepartment = $this->departmentService->update(
            $department,
            $request->validated()
        );

        return $this->successResponse(
            data: new DepartmentResource($updatedDepartment),
            message: 'Department updated successfully'
        );
    }

    public function destroy(Department $department): \Illuminate\Http\JsonResponse
    {
        $this->departmentService->delete($department);

        return $this->successResponse(
            message: 'Department deleted successfully'
        );
    }
} 