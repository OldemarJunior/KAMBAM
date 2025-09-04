<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class MoveHistory extends Model
{
    use HasFactory;

    protected $fillable = [
        'card_id',
        'board_id',
        'from_column_id',
        'to_column_id',
        'type',
        'by_user_id',
        'at',
    ];

    protected $casts = [
        'at' => 'datetime',
    ];

    public function card()
    {
        return $this->belongsTo(Card::class);
    }

    public function board()
    {
        return $this->belongsTo(Board::class);
    }

    public function fromColumn()
    {
        return $this->belongsTo(Column::class, 'from_column_id');
    }

    public function toColumn()
    {
        return $this->belongsTo(Column::class, 'to_column_id');
    }

    public function user()
    {
        return $this->belongsTo(User::class, 'by_user_id');
    }

    public static function logCreated(Card $card, User $user): void
    {
        self::create([
            'card_id' => $card->id,
            'board_id' => $card->board_id,
            'to_column_id' => $card->column_id,
            'type' => 'created',
            'by_user_id' => $user->id,
            'at' => now(),
        ]);
    }

    public static function logMoved(Card $card, int $fromColumnId, int $toColumnId, User $user): void
    {
        self::create([
            'card_id' => $card->id,
            'board_id' => $card->board_id,
            'from_column_id' => $fromColumnId,
            'to_column_id' => $toColumnId,
            'type' => 'moved',
            'by_user_id' => $user->id,
            'at' => now(),
        ]);
    }

    public static function logUpdated(Card $card, User $user): void
    {
        self::create([
            'card_id' => $card->id,
            'board_id' => $card->board_id,
            'type' => 'updated',
            'by_user_id' => $user->id,
            'at' => now(),
        ]);
    }

    public static function logDeleted(Card $card, User $user): void
    {
        self::create([
            'card_id' => $card->id,
            'board_id' => $card->board_id,
            'from_column_id' => $card->column_id,
            'type' => 'deleted',
            'by_user_id' => $user->id,
            'at' => now(),
        ]);
    }
}