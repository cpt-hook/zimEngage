<?php
declare(strict_types=1);

namespace App\Policies;

use App\Models\Attachment;
use App\Models\User;

final class AttachmentPolicy
{
    public function delete(User $user, Attachment $attachment): bool
    {
        // Customize this based on your requirements
        return $user->id === $attachment->uploaded_by
            || $user->hasRole('admin');
    }
} 