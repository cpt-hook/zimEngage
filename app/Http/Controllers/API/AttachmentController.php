<?php

declare(strict_types=1);

namespace App\Http\Controllers\API;

use App\Http\Requests\AttachmentRequest;
use App\Http\Resources\AttachmentResource;
use App\Models\Attachment;
use App\Services\AttachmentService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;
use Illuminate\Support\Facades\Storage;

final class AttachmentController extends BaseController
{
    public function __construct(
        private readonly AttachmentService $attachmentService
    ) {}

    public function index(): AnonymousResourceCollection
    {
        $attachments = Attachment::query()->paginate();
        return AttachmentResource::collection($attachments);
    }

    public function store(AttachmentRequest $request): JsonResponse
    {
        $attachment = $this->attachmentService->store(
            $request->file('file'),
            $request->validated(),
            $request->user()
        );

        return $this->successResponse(
            data: new AttachmentResource($attachment),
            message: 'File uploaded successfully',
            status: 201
        );
    }

    public function show(Attachment $attachment): JsonResponse
    {
        return $this->sendResponse(new AttachmentResource($attachment), 'Attachment retrieved successfully');
    }

    public function destroy(Attachment $attachment): JsonResponse
    {
        $this->authorize('delete', $attachment);
        
        $this->attachmentService->delete($attachment);

        return $this->successResponse(
            message: 'File deleted successfully'
        );
    }
} 