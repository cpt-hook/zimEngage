<?php

declare(strict_types=1);

namespace App\Services;

use App\Models\Announcement;
use Illuminate\Foundation\Auth\User;

final readonly class AnnouncementService
{
    public function create(array $data, User $user): Announcement
    {
        return Announcement::create([
            ...$data,
            'created_by' => $user->id,
        ]);
    }

    public function update(Announcement $announcement, array $data): Announcement
    {
        $announcement->update($data);
        return $announcement->refresh();
    }

    public function delete(Announcement $announcement): void
    {
        $announcement->delete();
    }
} 