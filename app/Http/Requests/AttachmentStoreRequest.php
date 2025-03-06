<?php

declare(strict_types=1);

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

final class AttachmentStoreRequest extends FormRequest
{
    public function rules(): array
    {
        return [
            'file' => [
                'required',
                'file',
                'max:10240', // 10MB max
                'mimes:jpeg,png,pdf,doc,docx,xls,xlsx,zip,rar', // Add allowed file types
            ],
            'attachable_type' => ['required', 'string'],
            'attachable_id' => ['required', 'integer', 'exists:' . $this->attachable_type . ',id'],
        ];
    }
} 