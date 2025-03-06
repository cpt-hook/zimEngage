<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreatePoliciesTable extends Migration
{
    public function up()
    {
        Schema::create('policies', function (Blueprint $table) {
            $table->id();
            $table->string('title');
            $table->foreignId('category_id')->constrained('policy_categories');
            $table->text('summary_en');
            $table->text('summary_sn')->nullable();
            $table->json('objectives_en');
            $table->json('objectives_sn')->nullable();
            $table->text('implementation_en');
            $table->text('implementation_sn')->nullable();
            $table->text('impact_en');
            $table->text('impact_sn')->nullable();
            $table->string('status')->default('draft');
            $table->foreignId('created_by')->constrained('users');
            $table->timestamp('published_at')->nullable();
            $table->integer('order')->default(0);
            $table->timestamps();

            $table->index('status');
            $table->index('order');
            $table->index('published_at');
        });

        Schema::create('policy_tag', function (Blueprint $table) {
            $table->foreignId('policy_id')->constrained()->cascadeOnDelete();
            $table->foreignId('tag_id')->constrained()->cascadeOnDelete();
            $table->primary(['policy_id', 'tag_id']);
        });
    }

    public function down()
    {
        Schema::dropIfExists('policy_tag');
        Schema::dropIfExists('policies');
    }
} 