<?php

declare(strict_types=1);

namespace App\Policies;

use App\Models\Setting;
use App\Models\User;

final class SettingPolicy
{
    public function viewAny(User $user): bool
    {
        return true; // Everyone can view settings, filtered by is_public
    }

    public function view(User $user, Setting $setting): bool
    {
        return $user->isAdmin() || $setting->is_public;
    }

    public function create(User $user): bool
    {
        return $user->isAdmin();
    }

    public function update(User $user, Setting $setting): bool
    {
        return $user->isAdmin();
    }

    public function delete(User $user, Setting $setting): bool
    {
        return $user->isAdmin();
    }
}