<?php

declare(strict_types=1);

namespace App\Http\Controllers\API;

use App\Http\Requests\AnnouncementStoreRequest;
use App\Http\Requests\AnnouncementUpdateRequest;
use App\Http\Resources\AnnouncementResource;
use App\Models\Announcement;
use App\Services\AnnouncementService;

final class AnnouncementController extends BaseController
{
    public function __construct(
        private readonly AnnouncementService $announcementService
    ) {}

    public function index(): \Illuminate\Http\JsonResponse
    {
        $announcements = Announcement::query()
            ->active()
            ->current()
            ->with('creator')
            ->get();

        return $this->successResponse(
            AnnouncementResource::collection($announcements)
        );
    }

    public function store(AnnouncementStoreRequest $request): \Illuminate\Http\JsonResponse
    {
        $announcement = $this->announcementService->create(
            $request->validated(),
            $request->user()
        );

        return $this->successResponse(
            data: new AnnouncementResource($announcement),
            message: 'Announcement created successfully',
            status: 201
        );
    }

    public function update(
        AnnouncementUpdateRequest $request,
        Announcement $announcement
    ): \Illuminate\Http\JsonResponse {
        $updatedAnnouncement = $this->announcementService->update(
            $announcement,
            $request->validated()
        );

        return $this->successResponse(
            data: new AnnouncementResource($updatedAnnouncement),
            message: 'Announcement updated successfully'
        );
    }

    public function destroy(Announcement $announcement): \Illuminate\Http\JsonResponse
    {
        $this->announcementService->delete($announcement);

        return $this->successResponse(
            message: 'Announcement deleted successfully'
        );
    }
} 