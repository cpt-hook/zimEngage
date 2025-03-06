<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreatePolicyCategoriesTable extends Migration
{
    public function up()
    {
        Schema::create('policy_categories', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('slug')->unique();
            $table->string('description')->nullable();
            $table->foreignId('department_id')->constrained();
            $table->string('icon')->nullable();
            $table->integer('order')->default(0);
            $table->timestamps();

            $table->index('order');
        });
    }

    public function down()
    {
        Schema::dropIfExists('policy_categories');
    }
} 