<?php

declare(strict_types=1);

namespace App\Http\Controllers\API;

use App\Http\Requests\PolicyCategoryStoreRequest;
use App\Http\Requests\PolicyCategoryUpdateRequest;
use App\Http\Resources\PolicyCategoryResource;
use App\Models\PolicyCategory;
use App\Services\PolicyCategoryService;

final class PolicyCategoryController extends BaseController
{
    public function __construct(
        private readonly PolicyCategoryService $policyCategoryService
    ) {}

    public function index(): \Illuminate\Http\JsonResponse
    {
        $categories = PolicyCategory::query()
            ->with(['department', 'policies'])
            ->get();

        return $this->successResponse(
            PolicyCategoryResource::collection($categories)
        );
    }

    public function store(PolicyCategoryStoreRequest $request): \Illuminate\Http\JsonResponse
    {
        $category = $this->policyCategoryService->create($request->validated());

        return $this->successResponse(
            data: new PolicyCategoryResource($category),
            message: 'Category created successfully',
            status: 201
        );
    }

    public function show(PolicyCategory $category): \Illuminate\Http\JsonResponse
    {
        return $this->successResponse(
            new PolicyCategoryResource($category->load(['department', 'policies']))
        );
    }

    public function update(
        PolicyCategoryUpdateRequest $request,
        PolicyCategory $category
    ): \Illuminate\Http\JsonResponse {
        $updatedCategory = $this->policyCategoryService->update(
            $category,
            $request->validated()
        );

        return $this->successResponse(
            data: new PolicyCategoryResource($updatedCategory),
            message: 'Category updated successfully'
        );
    }

    public function destroy(PolicyCategory $category): \Illuminate\Http\JsonResponse
    {
        $this->policyCategoryService->delete($category);

        return $this->successResponse(
            message: 'Category deleted successfully'
        );
    }
} 