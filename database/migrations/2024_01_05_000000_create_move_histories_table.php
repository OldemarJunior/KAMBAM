<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('move_histories', function (Blueprint $table) {
            $table->id();
            $table->foreignId('card_id')->constrained('cards')->onDelete('cascade');
            $table->foreignId('board_id')->constrained('boards')->onDelete('cascade');
            $table->foreignId('from_column_id')->nullable()->constrained('columns')->onDelete('cascade');
            $table->foreignId('to_column_id')->nullable()->constrained('columns')->onDelete('cascade');
            $table->enum('type', ['created', 'moved', 'updated', 'deleted']);
            $table->foreignId('by_user_id')->constrained('users')->onDelete('cascade');
            $table->timestamp('at')->useCurrent();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('move_histories');
    }
};