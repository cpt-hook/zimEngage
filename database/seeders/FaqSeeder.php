<?php

declare(strict_types=1);

namespace Database\Seeders;

use App\Models\Faq;
use Illuminate\Database\Seeder;

final class FaqSeeder extends Seeder
{
    public function run(): void
    {
        $faqs = [
            [
                'category_id' => 1,
                'question' => 'How can I submit feedback on a policy?',
                'answer' => 'You can submit feedback by navigating to the policy page and clicking the "Submit Feedback" button.',
            ],
            [
                'category_id' => 1,
                'question' => 'How long does it take to get a response?',
                'answer' => 'We aim to respond to all feedback within 5 working days.',
            ],
            [
                'category_id' => 2,
                'question' => 'What happens after I submit feedback?',
                'answer' => 'Your feedback is reviewed by the relevant department and you will be notified of any updates.',
            ],
        ];

        foreach ($faqs as $faq) {
            Faq::create($faq);
        }
    }
} 