<?php
declare(strict_types=1);

namespace App\Services;

use App\Models\Comment;
use App\Models\Policy;
use Illuminate\Foundation\Auth\User;

final readonly class CommentService
{
    public function create(Policy $policy, array $data, User $user): Comment
    {
        return $policy->comments()->create([
            ...$data,
            'user_id' => $user->id,
            'is_approved' => $user->isAdmin(),
        ]);
    }

    public function update(Comment $comment, array $data): Comment
    {
        $comment->update($data);
        return $comment->refresh();
    }

    public function delete(Comment $comment): void
    {
        $comment->delete();
    }

    public function approve(Comment $comment): Comment
    {
        $comment->update(['is_approved' => true]);
        return $comment->refresh();
    }
} 