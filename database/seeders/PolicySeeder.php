<?php

namespace Database\Seeders;

use App\Models\Policy;
use App\Models\PolicyCategory;
use App\Models\User;
use Illuminate\Database\Seeder;

class PolicySeeder extends Seeder
{
    public function run(): void
    {
        $admin = User::where('email', 'admin@govvoice.co.zw')->first();
        
        // Get the Agriculture category
        $category = PolicyCategory::where('name', 'Agriculture')->first();

        if ($admin && $category) {
            Policy::create([
                'title' => 'Agricultural Modernization Policy',
                'category_id' => $category->id,
                'summary_en' => 'Focuses on modernizing farming practices.',
                'summary_sn' => 'Kuwedzera unyanzvi hwekurima.',
                'objectives_en' => ['Increase productivity', 'Improve food security'],
                'objectives_sn' => ['Kuwedzera zvibereko', 'Kuwedzera kudya'],
                'implementation_en' => 'Five year implementation plan',
                'implementation_sn' => 'Hurongwa hwemakore mashanu',
                'impact_en' => 'Benefit 500,000 farmers',
                'impact_sn' => 'Kubatsira varimi 500,000',
                'status' => 'published',
                'created_by' => $admin->id,
            ]);
        }

        // Add more policies as needed...
    }
} 