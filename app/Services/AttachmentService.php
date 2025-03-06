<?php
declare(strict_types=1);

namespace App\Services;

use App\Models\Attachment;
use Illuminate\Foundation\Auth\User;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Storage;

final readonly class AttachmentService
{
    public function store(
        UploadedFile $file,
        array $data,
        User $user
    ): Attachment {
        $path = $file->store('attachments', 'public');

        return Attachment::create([
            'name' => $file->getClientOriginalName(),
            'file_path' => $path,
            'mime_type' => $file->getMimeType(),
            'size' => $file->getSize(),
            'attachable_type' => $data['attachable_type'],
            'attachable_id' => $data['attachable_id'],
            'uploaded_by' => $user->id,
        ]);
    }

    public function delete(Attachment $attachment): void
    {
        Storage::disk('public')->delete($attachment->file_path);
        $attachment->delete();
    }
} 