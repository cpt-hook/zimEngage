<?php

declare(strict_types=1);

namespace App\Services;

use App\Models\Faq;

final readonly class FaqService
{
    public function create(array $data): Faq
    {
        return Faq::create($data);
    }

    public function update(Faq $faq, array $data): Faq
    {
        $faq->update($data);
        return $faq->refresh();
    }

    public function delete(Faq $faq): void
    {
        $faq->delete();
    }
} 