<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Column extends Model
{
    use HasFactory;

    protected $fillable = [
        'board_id',
        'name',
        'order',
        'wip_limit',
    ];

    public function board()
    {
        return $this->belongsTo(Board::class);
    }

    public function cards()
    {
        return $this->hasMany(Card::class)->orderBy('position');
    }

    public function canAddCard(): bool
    {
        return $this->cards()->count() < $this->wip_limit;
    }

    public function getCardsCount(): int
    {
        return $this->cards()->count();
    }

    public function isAtWipLimit(): bool
    {
        return $this->getCardsCount() >= $this->wip_limit;
    }
}