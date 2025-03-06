<?php

declare(strict_types=1);

namespace App\Http\Controllers\API;

use App\Http\Requests\CommentStoreRequest;
use App\Http\Requests\CommentUpdateRequest;
use App\Http\Resources\CommentResource;
use App\Models\Comment;
use App\Models\Policy;
use App\Services\CommentService;

final class CommentController extends BaseController
{
    public function __construct(
        private readonly CommentService $commentService
    ) {}

    public function index(Policy $policy): \Illuminate\Http\JsonResponse
    {
        $comments = $policy->comments()
            ->with(['user', 'replies.user'])
            ->parentComments()
            ->get();

        return $this->successResponse(
            CommentResource::collection($comments)
        );
    }

    public function store(
        CommentStoreRequest $request,
        Policy $policy
    ): \Illuminate\Http\JsonResponse {
        $comment = $this->commentService->create(
            $policy,
            $request->validated(),
            $request->user()
        );

        return $this->successResponse(
            data: new CommentResource($comment->load('user')),
            message: 'Comment added successfully',
            status: 201
        );
    }

    public function update(
        CommentUpdateRequest $request,
        Comment $comment
    ): \Illuminate\Http\JsonResponse {
        $this->authorize('update', $comment);

        $updatedComment = $this->commentService->update(
            $comment,
            $request->validated()
        );

        return $this->successResponse(
            data: new CommentResource($updatedComment),
            message: 'Comment updated successfully'
        );
    }

    public function destroy(Comment $comment): \Illuminate\Http\JsonResponse
    {
        $this->authorize('delete', $comment);
        
        $this->commentService->delete($comment);

        return $this->successResponse(
            message: 'Comment deleted successfully'
        );
    }

    public function approve(Comment $comment): \Illuminate\Http\JsonResponse
    {
        $this->authorize('approve', $comment);

        $approvedComment = $this->commentService->approve($comment);

        return $this->successResponse(
            data: new CommentResource($approvedComment),
            message: 'Comment approved successfully'
        );
    }
} 