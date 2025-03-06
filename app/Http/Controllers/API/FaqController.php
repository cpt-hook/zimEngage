<?php

declare(strict_types=1);

namespace App\Http\Controllers\API;

use App\Http\Requests\FaqStoreRequest;
use App\Http\Requests\FaqUpdateRequest;
use App\Http\Resources\FaqCategoryResource;
use App\Http\Resources\FaqResource;
use App\Models\Faq;
use App\Models\FaqCategory;
use App\Services\FaqService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;

final class FaqController extends BaseController
{
    public function __construct(
        private readonly FaqService $faqService
    ) {}

    public function index(): \Illuminate\Http\JsonResponse
    {
        $faqs = FaqCategory::query()
            ->with(['faqs' => function ($query) {
                $query->published()->ordered();
            }])
            ->ordered()
            ->get();

        return $this->successResponse(
            FaqCategoryResource::collection($faqs)
        );
    }

    public function store(FaqStoreRequest $request): \Illuminate\Http\JsonResponse
    {
        $faq = $this->faqService->create($request->validated());
        
        return $this->successResponse(
            data: new FaqResource($faq),
            message: 'FAQ created successfully',
            status: 201
        );
    }

    public function update(FaqUpdateRequest $request, Faq $faq): \Illuminate\Http\JsonResponse
    {
        $updatedFaq = $this->faqService->update($faq, $request->validated());
        
        return $this->successResponse(
            data: new FaqResource($updatedFaq),
            message: 'FAQ updated successfully'
        );
    }

    public function destroy(Faq $faq): \Illuminate\Http\JsonResponse
    {
        $this->faqService->delete($faq);
        
        return $this->successResponse(
            message: 'FAQ deleted successfully'
        );
    }
} 