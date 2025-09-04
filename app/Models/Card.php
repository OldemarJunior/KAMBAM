<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Card extends Model
{
    use HasFactory;

    protected $fillable = [
        'board_id',
        'column_id',
        'title',
        'description',
        'position',
        'created_by',
    ];

    public function board()
    {
        return $this->belongsTo(Board::class);
    }

    public function column()
    {
        return $this->belongsTo(Column::class);
    }

    public function creator()
    {
        return $this->belongsTo(User::class, 'created_by');
    }

    public function moveHistories()
    {
        return $this->hasMany(MoveHistory::class)->orderBy('at', 'desc');
    }

    public function getNextPosition(Column $column): int
    {
        return $column->cards()->max('position') + 1;
    }

    public function moveToTop(Column $column): void
    {
        $column->cards()->where('position', '>=', 1)->increment('position');
        $this->update(['position' => 1, 'column_id' => $column->id]);
    }

    public function moveToBottom(Column $column): void
    {
        $nextPosition = $this->getNextPosition($column);
        $this->update(['position' => $nextPosition, 'column_id' => $column->id]);
    }
}