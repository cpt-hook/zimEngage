<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Feedback extends Model
{

    protected $fillable = [
        'user_id',
        'type',
        'message',
        'status',
        'response',
        'sentiment_score',
        'sentiment_label',
        'assigned_to',
    ];

    public function user()
    {
        return $this->belongsTo(User::class);
    } /** @use HasFactory<\Database\Factories\FeedbackFactory> */
    use HasFactory;
}
