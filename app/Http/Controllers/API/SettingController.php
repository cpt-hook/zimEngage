<?php

declare(strict_types=1);

namespace App\Http\Controllers\API;

use App\Http\Requests\SettingRequest;
use App\Http\Resources\SettingResource;
use App\Models\Setting;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;

final class SettingController extends BaseController
{
    public function index(): AnonymousResourceCollection
    {
        $settings = Setting::query()
            ->when(!auth()->user()?->isAdmin(), function ($query) {
                $query->where('is_public', true);
            })
            ->get();

        return SettingResource::collection($settings);
    }

    public function store(SettingRequest $request): JsonResponse
    {
        $this->authorize('create', Setting::class);

        $setting = Setting::create($request->validated());
        return $this->sendResponse(new SettingResource($setting), 'Setting created successfully');
    }

    public function show(Setting $setting): JsonResponse
    {
        $this->authorize('view', $setting);

        return $this->sendResponse(new SettingResource($setting), 'Setting retrieved successfully');
    }

    public function update(SettingRequest $request, Setting $setting): JsonResponse
    {
        $this->authorize('update', $setting);

        $setting->update($request->validated());
        return $this->sendResponse(new SettingResource($setting), 'Setting updated successfully');
    }

    public function destroy(Setting $setting): JsonResponse
    {
        $this->authorize('delete', $setting);

        $setting->delete();
        return $this->sendResponse(null, 'Setting deleted successfully');
    }
} 