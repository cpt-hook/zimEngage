<?php
declare(strict_types=1);

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

final class DepartmentResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'code' => $this->code,
            'description' => $this->description,
            'head_of_department' => $this->head_of_department,
            'email' => $this->email,
            'phone' => $this->phone,
            'is_active' => $this->is_active,
            'policy_categories' => PolicyCategoryResource::collection(
                $this->whenLoaded('policyCategories')
            ),
            'created_at' => $this->created_at,
            'updated_at' => $this->updated_at,
        ];
    }
} 